"""
PlexiChat Client Settings Service

A comprehensive database-backed service for managing user client settings with
support for key-value pairs, image storage, validation, rate limiting, and security controls.
"""

import asyncio
import base64
import hashlib
import json
import logging
import mimetypes
import os
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from dataclasses import dataclass, field
from functools import wraps

try:
    from plexichat.core.database.manager import database_manager, get_session
    from plexichat.src.plexichat.core.config_manager import get_config
except ImportError:
    # Fallback for standalone execution
    database_manager = None
    get_session = None
    def get_config(section): return None

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


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_limit: int = 10
    cleanup_interval: int = 300  # 5 minutes


class RateLimiter:
    """Simple in-memory rate limiter for client settings operations."""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.requests: Dict[str, List[float]] = {}
        self.lock = asyncio.Lock()
        self.last_cleanup = time.time()
    
    async def check_rate_limit(self, user_id: str) -> bool:
        """Check if user is within rate limits."""
        async with self.lock:
            now = time.time()
            
            # Cleanup old entries periodically
            if now - self.last_cleanup > self.config.cleanup_interval:
                await self._cleanup_old_entries(now)
                self.last_cleanup = now
            
            if user_id not in self.requests:
                self.requests[user_id] = []
            
            user_requests = self.requests[user_id]
            
            # Remove requests older than 1 hour
            cutoff_hour = now - 3600
            user_requests[:] = [req_time for req_time in user_requests if req_time > cutoff_hour]
            
            # Check hourly limit
            if len(user_requests) >= self.config.requests_per_hour:
                return False
            
            # Check minute limit
            cutoff_minute = now - 60
            recent_requests = [req_time for req_time in user_requests if req_time > cutoff_minute]
            if len(recent_requests) >= self.config.requests_per_minute:
                return False
            
            # Check burst limit (last 10 seconds)
            cutoff_burst = now - 10
            burst_requests = [req_time for req_time in user_requests if req_time > cutoff_burst]
            if len(burst_requests) >= self.config.burst_limit:
                return False
            
            # Record this request
            user_requests.append(now)
            return True
    
    async def _cleanup_old_entries(self, now: float):
        """Remove old rate limit entries."""
        cutoff = now - 3600  # Keep last hour
        for user_id in list(self.requests.keys()):
            self.requests[user_id] = [
                req_time for req_time in self.requests[user_id] 
                if req_time > cutoff
            ]
            if not self.requests[user_id]:
                del self.requests[user_id]


def rate_limited(rate_limiter: RateLimiter):
    """Decorator to apply rate limiting to methods."""
    def decorator(func):
        @wraps(func)
        async def wrapper(self, user_id: str, *args, **kwargs):
            if not await rate_limiter.check_rate_limit(user_id):
                raise RateLimitError("Rate limit exceeded")
            return await func(self, user_id, *args, **kwargs)
        return wrapper
    return decorator


class SettingValidator:
    """Validates setting keys, values, and types."""
    
    def __init__(self, limits: SettingLimits):
        self.limits = limits
    
    def validate_key(self, key: str) -> None:
        """Validate setting key."""
        if not key:
            raise ValidationError("Setting key cannot be empty")
        
        if len(key) > self.limits.max_key_length:
            raise ValidationError(f"Setting key too long (max {self.limits.max_key_length} characters)")
        
        # Key should contain only alphanumeric characters, underscores, dots, and hyphens
        if not all(c.isalnum() or c in '._-' for c in key):
            raise ValidationError("Setting key contains invalid characters")
    
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
    rate limiting, and security controls.
    """
    
    def __init__(self, 
                 limits: Optional[SettingLimits] = None,
                 rate_limit_config: Optional[RateLimitConfig] = None):
        self.limits = limits or SettingLimits()
        self.rate_limiter = RateLimiter(rate_limit_config or RateLimitConfig())
        self.validator = SettingValidator(self.limits)
        self.logger = logging.getLogger(__name__)
        self._initialized = False
    
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
                        "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                        "updated_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                        "size_bytes": "INTEGER DEFAULT 0",
                        "UNIQUE": "(user_id, setting_key)" if database_manager.config.db_type == "sqlite" else "",
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
    
    @rate_limited(lambda self: self.rate_limiter)
    async def get_user_settings(self, user_id: str, user_permissions: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
        """Get all settings for a user."""
        await self.initialize()
        
        if not database_manager:
            return []
        
        try:
            async with get_session(user_permissions) as session:
                query = """
                    SELECT setting_key, setting_value, setting_type, updated_at, size_bytes
                    FROM client_settings 
                    WHERE user_id = :user_id
                    ORDER BY setting_key
                """
                rows = await session.fetchall(query, {"user_id": user_id})
                
                settings = []
                for row in rows:
                    setting = {
                        "setting_key": row["setting_key"],
                        "setting_value": self._deserialize_value(row["setting_value"], row["setting_type"]),
                        "setting_type": row["setting_type"],
                        "updated_at": row["updated_at"],
                        "size_bytes": row["size_bytes"]
                    }
                    settings.append(setting)
                
                return settings
                
        except Exception as e:
            self.logger.error(f"Failed to get user settings for {user_id}: {e}")
            raise
    
    @rate_limited(lambda self: self.rate_limiter)
    async def get_setting(self, user_id: str, key: str, user_permissions: Optional[Set[str]] = None) -> Optional[Dict[str, Any]]:
        """Get a specific setting for a user."""
        await self.initialize()
        
        if not database_manager:
            return None
        
        self.validator.validate_key(key)
        
        try:
            async with get_session(user_permissions) as session:
                query = """
                    SELECT setting_value, setting_type, updated_at, size_bytes
                    FROM client_settings 
                    WHERE user_id = :user_id AND setting_key = :key
                """
                row = await session.fetchone(query, {"user_id": user_id, "key": key})
                
                if not row:
                    return None
                
                return {
                    "setting_key": key,
                    "setting_value": self._deserialize_value(row["setting_value"], row["setting_type"]),
                    "setting_type": row["setting_type"],
                    "updated_at": row["updated_at"],
                    "size_bytes": row["size_bytes"]
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get setting {key} for user {user_id}: {e}")
            raise
    
    @rate_limited(lambda self: self.rate_limiter)
    async def set_setting(self, 
                         user_id: str, 
                         key: str, 
                         value: Any, 
                         setting_type: Union[str, SettingType] = SettingType.STRING,
                         user_permissions: Optional[Set[str]] = None) -> Dict[str, Any]:
        """Set or update a setting for a user."""
        await self.initialize()
        
        if not database_manager:
            return {"setting_key": key, "setting_value": value, "updated_at": datetime.utcnow()}
        
        # Validate inputs
        self.validator.validate_key(key)
        
        if isinstance(setting_type, str):
            setting_type = SettingType(setting_type)
        
        validated_value = self.validator.validate_value(value, setting_type)
        
        # Check storage limits
        await self._check_storage_limits(user_id, key, validated_value, user_permissions)
        
        try:
            async with get_session(user_permissions) as session:
                serialized_value = self._serialize_value(validated_value, setting_type)
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
                            "created_at": now,
                            "updated_at": now,
                            "size_bytes": size_bytes
                        }
                    )
                
                await session.commit()
                
                return {
                    "setting_key": key,
                    "setting_value": validated_value,
                    "setting_type": setting_type.value,
                    "updated_at": now,
                    "size_bytes": size_bytes
                }
                
        except Exception as e:
            self.logger.error(f"Failed to set setting {key} for user {user_id}: {e}")
            raise
    
    @rate_limited(lambda self: self.rate_limiter)
    async def delete_setting(self, user_id: str, key: str, user_permissions: Optional[Set[str]] = None) -> bool:
        """Delete a setting for a user."""
        await self.initialize()
        
        if not database_manager:
            return True
        
        self.validator.validate_key(key)
        
        try:
            async with get_session(user_permissions) as session:
                result = await session.delete(
                    "client_settings",
                    {"user_id": user_id, "setting_key": key}
                )
                await session.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to delete setting {key} for user {user_id}: {e}")
            raise
    
    @rate_limited(lambda self: self.rate_limiter)
    async def bulk_update_settings(self, 
                                  user_id: str, 
                                  settings: Dict[str, Any],
                                  user_permissions: Optional[Set[str]] = None) -> Dict[str, Any]:
        """Bulk update multiple settings for a user."""
        await self.initialize()
        
        if not database_manager:
            return {"updated_count": len(settings)}
        
        if len(settings) > 100:  # Limit bulk operations
            raise ValidationError("Too many settings in bulk update (max 100)")
        
        updated_count = 0
        errors = []
        
        try:
            async with get_session(user_permissions) as session:
                for key, value in settings.items():
                    try:
                        # Validate each setting
                        self.validator.validate_key(key)
                        
                        # Determine type from value
                        setting_type = self._infer_type(value)
                        validated_value = self.validator.validate_value(value, setting_type)
                        
                        # Check storage limits for this setting
                        await self._check_storage_limits(user_id, key, validated_value, user_permissions, session)
                        
                        serialized_value = self._serialize_value(validated_value, setting_type)
                        size_bytes = len(serialized_value.encode('utf-8')) if serialized_value else 0
                        now = datetime.utcnow()
                        
                        # Check if setting exists
                        existing = await session.fetchone(
                            "SELECT id FROM client_settings WHERE user_id = :user_id AND setting_key = :key",
                            {"user_id": user_id, "key": key}
                        )
                        
                        if existing:
                            await session.update(
                                "client_settings",
                                {
                                    "setting_value": serialized_value,
                                    "setting_type": setting_type.value,
                                    "updated_at": now,
                                    "size_bytes": size_bytes
                                },
                                {"user_id": user_id, "setting_key": key}
                            )
                        else:
                            await session.insert(
                                "client_settings",
                                {
                                    "user_id": user_id,
                                    "setting_key": key,
                                    "setting_value": serialized_value,
                                    "setting_type": setting_type.value,
                                    "created_at": now,
                                    "updated_at": now,
                                    "size_bytes": size_bytes
                                }
                            )
                        
                        updated_count += 1
                        
                    except Exception as e:
                        errors.append({"key": key, "error": str(e)})
                        self.logger.warning(f"Failed to update setting {key}: {e}")
                
                await session.commit()
                
                result = {"updated_count": updated_count}
                if errors:
                    result["errors"] = errors
                
                return result
                
        except Exception as e:
            self.logger.error(f"Failed to bulk update settings for user {user_id}: {e}")
            raise
    
    async def get_user_stats(self, user_id: str, user_permissions: Optional[Set[str]] = None) -> Dict[str, Any]:
        """Get storage statistics for a user."""
        await self.initialize()
        
        if not database_manager:
            return {"total_settings": 0, "total_storage_bytes": 0}
        
        try:
            async with get_session(user_permissions) as session:
                query = """
                    SELECT 
                        COUNT(*) as total_settings,
                        COALESCE(SUM(size_bytes), 0) as total_storage_bytes,
                        COUNT(CASE WHEN setting_type = 'image' THEN 1 END) as image_count,
                        COUNT(CASE WHEN setting_type = 'binary' THEN 1 END) as binary_count
                    FROM client_settings 
                    WHERE user_id = :user_id
                """
                row = await session.fetchone(query, {"user_id": user_id})
                
                return {
                    "total_settings": row["total_settings"] or 0,
                    "total_storage_bytes": row["total_storage_bytes"] or 0,
                    "image_count": row["image_count"] or 0,
                    "binary_count": row["binary_count"] or 0,
                    "storage_limit_bytes": self.limits.max_total_storage_per_user,
                    "settings_limit": self.limits.max_settings_per_user
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get user stats for {user_id}: {e}")
            return {"total_settings": 0, "total_storage_bytes": 0}
    
    async def get_user_images(self, user_id: str, user_permissions: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
        """Get all image settings for a user."""
        await self.initialize()
        
        if not database_manager:
            return []
        
        try:
            async with get_session(user_permissions) as session:
                query = """
                    SELECT setting_key, setting_value, updated_at, size_bytes
                    FROM client_settings 
                    WHERE user_id = :user_id AND setting_type = 'image'
                    ORDER BY updated_at DESC
                """
                rows = await session.fetchall(query, {"user_id": user_id})
                
                images = []
                for row in rows:
                    image_data = self._deserialize_value(row["setting_value"], "image")
                    images.append({
                        "setting_key": row["setting_key"],
                        "content_type": image_data.get("content_type", "image/jpeg"),
                        "size": row["size_bytes"],
                        "hash": image_data.get("hash"),
                        "updated_at": row["updated_at"]
                    })
                
                return images
                
        except Exception as e:
            self.logger.error(f"Failed to get user images for {user_id}: {e}")
            return []
    
    async def cleanup_expired_settings(self, days_old: int = 365) -> int:
        """Clean up old unused settings (admin operation)."""
        await self.initialize()
        
        if not database_manager:
            return 0
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            
            async with get_session() as session:
                result = await session.execute(
                    "DELETE FROM client_settings WHERE updated_at < :cutoff",
                    {"cutoff": cutoff_date}
                )
                await session.commit()
                
                # Get affected rows count (implementation depends on database)
                return getattr(result, 'rowcount', 0)
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup expired settings: {e}")
            return 0
    
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
                                   session=None) -> None:
        """Check if setting the value would exceed storage limits."""
        if not database_manager:
            return
        
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
        if current_key_size == 0 and current_settings >= self.limits.max_settings_per_user:
            raise StorageLimitError(f"Maximum number of settings exceeded ({self.limits.max_settings_per_user})")
        
        # Check total storage limit
        new_total_storage = current_storage - current_key_size + new_size
        if new_total_storage > self.limits.max_total_storage_per_user:
            raise StorageLimitError(f"Storage limit exceeded ({self.limits.max_total_storage_per_user} bytes)")


# Global service instance
client_settings_service = ClientSettingsService()


# Convenience functions for backward compatibility
async def get_user_settings(user_id: str, user_permissions: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    """Get all settings for a user."""
    return await client_settings_service.get_user_settings(user_id, user_permissions)


async def get_setting(user_id: str, key: str, user_permissions: Optional[Set[str]] = None) -> Optional[Dict[str, Any]]:
    """Get a specific setting for a user."""
    return await client_settings_service.get_setting(user_id, key, user_permissions)


async def set_setting(user_id: str, 
                     key: str, 
                     value: Any, 
                     setting_type: Union[str, SettingType] = SettingType.STRING,
                     user_permissions: Optional[Set[str]] = None) -> Dict[str, Any]:
    """Set or update a setting for a user."""
    return await client_settings_service.set_setting(user_id, key, value, setting_type, user_permissions)


async def delete_setting(user_id: str, key: str, user_permissions: Optional[Set[str]] = None) -> bool:
    """Delete a setting for a user."""
    return await client_settings_service.delete_setting(user_id, key, user_permissions)


async def bulk_update_settings(user_id: str, 
                              settings: Dict[str, Any],
                              user_permissions: Optional[Set[str]] = None) -> Dict[str, Any]:
    """Bulk update multiple settings for a user."""
    return await client_settings_service.bulk_update_settings(user_id, settings, user_permissions)


async def get_user_stats(user_id: str, user_permissions: Optional[Set[str]] = None) -> Dict[str, Any]:
    """Get storage statistics for a user."""
    return await client_settings_service.get_user_stats(user_id, user_permissions)


async def get_user_images(user_id: str, user_permissions: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    """Get all image settings for a user."""
    return await client_settings_service.get_user_images(user_id, user_permissions)