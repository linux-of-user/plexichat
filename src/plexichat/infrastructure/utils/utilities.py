# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import hashlib
import json
import logging
import re
import secrets
import threading
import time
import warnings
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar, Union

from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path

from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path

"""
import stat
import string
Common Utilities Module for PlexiChat
Provides shared functionality to reduce code duplication across the application.
"""

T = TypeVar('T')

@dataclass
class Result(Generic[T]):
    """Generic result wrapper for operations."""
    success: bool
    data: Optional[T] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    @classmethod
    def success_result(cls, data: T, metadata: Optional[Dict[str, Any]] = None) -> 'Result[T]':
        """Create a successful result."""
        return cls(success=True, data=data, metadata=metadata)

    @classmethod
    def error_result(cls, error: str, error_code: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> 'Result[T]':
        """Create an error result."""
        return cls(success=False, error=error, error_code=error_code, metadata=metadata)

class ConfigManager:
    """Centralized configuration management."""

    def __init__(self, config_file: str = "config/plexichat.json"):
        from pathlib import Path
        self.config_file = Path(config_file)
        self.config = {}
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        self._load_config()

    def _load_config(self):
        """Load configuration from file."""
        try:
            if self.config_file.exists() if self.config_file else False:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                self.logger.info(f"Configuration loaded from {self.config_file}")
            else:
                self._create_default_config()
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            self._create_default_config()

    def _create_default_config(self):
        """Create default configuration."""
        self.config = {
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "debug": False,
                "workers": 4,
                "secret_key": secrets.token_hex(32),
                "webhook_secret": secrets.token_hex(32)
            },
            "database": {
                "url": "sqlite:///./plexichat.db",
                "pool_size": 10,
                "timeout": 30,
                "backup_enabled": True,
                "backup_interval_hours": 6
            },
            "logging": {
                "level": "INFO",
                "file": "logs/plexichat.log",
                "max_files": 10,
                "max_size_mb": 100,
                "console_level": "INFO",
                "file_level": "DEBUG",
                "compress_backups": True,
                "capture_warnings": True
            },
            "security": {
                "session_timeout": 1800,
                "max_login_attempts": 5,
                "password_min_length": 12,
                "rate_limit_requests": 100,
                "rate_limit_window": 60,
                "force_https": False,
                "csrf_protection": True
            },
            "performance": {
                "cache_size": 1000,
                "cache_ttl": 3600,
                "enable_compression": True,
                "enable_monitoring": True,
                "monitoring_interval": 60
            },
            "testing": {
                "enabled": True,
                "interval_minutes": 30,
                "timeout_seconds": 30,
                "retry_count": 3,
                "save_results": True,
                "alert_on_failure": True
            },
            "backup": {
                "enabled": True,
                "shard_count": 5,
                "shard_size_mb": 50,
                "encryption_enabled": True,
                "auto_cleanup_days": 30,
                "distribution_enabled": True
            },
            "communication": {
                "max_message_length": 2000,
                "max_file_size_mb": 25,
                "allowed_file_types": ["jpg", "jpeg", "png", "gif", "pdf", "txt", "doc", "docx"],
                "enable_voice": True,
                "enable_video": True,
                "max_channels_per_server": 500,
                "max_users_per_server": 10000
            }
        }
        self.save_config()

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        """Get configuration value using dot notation."""
        with self.lock:
            keys = key.split('.')
            value = self.config

            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default

            return value

    def set(self, key: str, value: Any) -> bool:
        """Set configuration value using dot notation."""
        with self.lock:
            keys = key.split('.')
            config = self.config

            # Navigate to parent
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]

            # Set value
            config[keys[-1]] = value
            return self.save_config()

    def save_config(self) -> bool:
        """Save configuration to file."""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
            return False

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration."""
        with self.lock:
            return self.config.copy()

class FileManager:
    """Common file operations."""

    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> bool:
        """Ensure directory exists."""
        try:
            Path(path).mkdir(parents=True, exist_ok=True)
            return True
        except Exception:
            return False

    @staticmethod
    def safe_write_file(filepath: Union[str, Path], content: Union[str, bytes], backup: bool = True) -> Result[str]:
        """Safely write file with optional backup."""
        try:
            from pathlib import Path

            self.filepath = Path(filepath)

            # Create backup if requested and file exists
            if backup and filepath.exists():
                backup_path = filepath.with_suffix(f"{filepath.suffix}.backup")
                filepath.rename(backup_path)

            # Ensure directory exists
            filepath.parent.mkdir(parents=True, exist_ok=True)

            # Write file
            mode = 'w' if isinstance(content, str) else 'wb'
            with open(filepath, mode) as f:
                f.write(content)

            return Result.success_result(str(filepath))

        except Exception as e:
            return Result.error_result(f"Failed to write file: {e}")

    @staticmethod
    def safe_read_file(filepath: Union[str, Path], binary: bool = False) -> Result[Union[str, bytes]]:
        """Safely read file."""
        try:
            from pathlib import Path

            self.filepath = Path(filepath)

            if not filepath.exists():
                return Result.error_result("File not found", "FILE_NOT_FOUND")

            mode = 'rb' if binary else 'r'
            with open(filepath, mode) as f:
                content = f.read()

            return Result.success_result(content)

        except Exception as e:
            return Result.error_result(f"Failed to read file: {e}")

    @staticmethod
    def get_file_info(filepath: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """Get file information."""
        try:
            from pathlib import Path

            self.filepath = Path(filepath)
            if not filepath.exists():
                return None

            stat = filepath.stat()
            return {}
                "name": filepath.name,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime),
                "created": datetime.fromtimestamp(stat.st_ctime),
                "is_file": filepath.is_file(),
                "is_directory": filepath.is_dir()
            }
        except Exception:
            return None

class DateTimeUtils:
    """Common date/time utilities."""

    @staticmethod
    def now() -> datetime:
        """Get current datetime."""
        return datetime.now()

    @staticmethod
    def utc_now() -> datetime:
        """Get current UTC datetime."""
        return datetime.utcnow()

    @staticmethod
    def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Format datetime to string."""
        return dt.strftime(format_str)

    @staticmethod
    def parse_datetime(dt_str: str, format_str: str = "%Y-%m-%d %H:%M:%S") -> Optional[datetime]:
        """Parse datetime from string."""
        try:
            return datetime.strptime(dt_str, format_str)
        except ValueError:
            return None

    @staticmethod
    def time_ago(dt: datetime) -> str:
        """Get human-readable time ago string."""

        now = datetime().now()
        diff = now - dt

        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"

    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in seconds to human-readable string."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"

class StringUtils:
    """Common string utilities."""

    @staticmethod
    def generate_id(length: int = 8) -> str:
        """Generate random ID."""
        return secrets.token_urlsafe(length)[:length]

    @staticmethod
    def hash_string(text: str, algorithm: str = "sha256") -> str:
        """Hash string using specified algorithm."""
        hasher = hashlib.new(algorithm)
        hasher.update(text.encode('utf-8'))
        return hasher.hexdigest()

    @staticmethod
    def truncate(text: str, max_length: int, suffix: str = "...") -> str:
        """Truncate string to max length."""
        if len(text) <= max_length:
            return text
        return text[:max_length - len(suffix)] + suffix

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe filesystem use."""
        # Remove or replace invalid characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Remove leading/trailing spaces and dots
        sanitized = sanitized.strip(' .')
        # Limit length
        return sanitized[:255]

    @staticmethod
    def format_bytes(bytes_count: int) -> str:
        """Format bytes to human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"

class ValidationUtils:
    """Common validation utilities."""

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Validate URL format."""
        pattern = r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'
        return re.match(pattern, url) is not None

    @staticmethod
    def is_valid_port(port: Any) -> bool:
        """Validate port number."""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False

    @staticmethod
    def validate_required_fields(data: Dict[str, Any], required_fields: List[str]) -> Result[Dict[str, Any]]:
        """Validate required fields in data."""
        missing_fields = [field for field in required_fields if field not in data or data[field] is None]

        if missing_fields:
            return Result.error_result(
                f"Missing required fields: {', '.join(missing_fields)}",
                "MISSING_FIELDS",
                {"missing_fields": missing_fields}
            )

        return Result.success_result(data)

class RetryUtils:
    """Retry utilities for resilient operations."""

    @staticmethod
    def retry_with_backoff(
        func: Callable,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        backoff_factor: float = 2.0,
        exceptions: tuple = (Exception,)
    ) -> Any:
        """Retry function with exponential backoff."""
        for attempt in range(max_attempts):
            try:
                return func()
            except exceptions:
                if attempt == max_attempts - 1:
                    raise

                delay = min(base_delay * (backoff_factor ** attempt), max_delay)
                time.sleep(delay)

        raise RuntimeError("Max retry attempts exceeded")

# Decorators
def singleton(cls):
    """Singleton decorator."""
    instances = {}
    lock = threading.Lock()

    def get_instance(*args, **kwargs):
        if cls not in instances:
            with lock:
                if cls not in instances:
                    instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance

def log_execution(logger: Optional[logging.Logger] = None):
    """Decorator to log function execution."""
    def decorator(func):
        nonlocal logger
        if logger is None:
            logger = logging.getLogger(func.__module__)

        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            logger.debug(f"Starting {func.__name__}")

            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                logger.debug(f"Completed {func.__name__} in {duration:.3f}s")
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"Failed {func.__name__} after {duration:.3f}s: {e}")
                raise

        return wrapper
    return decorator

def deprecated(reason: str = ""):
    """Mark function as deprecated."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            warnings.warn(
                f"{func.__name__} is deprecated. {reason}",
                DeprecationWarning,
                stacklevel=2
            )
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Global instances
config_manager = ConfigManager()
file_manager = FileManager()

# Common constants
DEFAULT_ENCODING = 'utf-8'
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
DEFAULT_TIMEOUT = 30
DEFAULT_RETRY_ATTEMPTS = 3
