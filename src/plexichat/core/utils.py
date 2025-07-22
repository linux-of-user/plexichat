"""
PlexiChat Core Utilities
Consolidated utility functions for the entire application.
"""

import hashlib
import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class StringUtils:
    """String utility functions."""
    
    @staticmethod
    def generate_id(prefix: str = "") -> str:
        """Generate a unique ID."""
        return f"{prefix}{uuid.uuid4().hex[:8]}" if prefix else uuid.uuid4().hex[:12]
    
    @staticmethod
    def sanitize_string(text: str, max_length: int = 255) -> str:
        """Sanitize and truncate string."""
        if not isinstance(text, str):
            text = str(text)
        # Remove control characters and limit length
        sanitized = ''.join(char for char in text if ord(char) >= 32)
        return sanitized[:max_length]
    
    @staticmethod
    def safe_filename(filename: str) -> str:
        """Create a safe filename."""
        import re
        # Remove unsafe characters
        safe = re.sub(r'[<>:"/\\|?*]', '_', filename)
        return safe[:255]  # Limit length


class DateTimeUtils:
    """DateTime utility functions."""
    
    @staticmethod
    def current_timestamp() -> str:
        """Get current timestamp as ISO string."""
        return datetime.now(timezone.utc).isoformat()
    
    @staticmethod
    def timestamp_to_datetime(timestamp: Union[str, float, int]) -> datetime:
        """Convert timestamp to datetime."""
        if isinstance(timestamp, str):
            return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in human readable format."""
        if seconds < 1:
            return f"{seconds*1000:.1f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"


class HashUtils:
    """Hashing utility functions."""
    
    @staticmethod
    def hash_string(text: str, algorithm: str = "sha256") -> str:
        """Hash a string."""
        hasher = hashlib.new(algorithm)
        hasher.update(text.encode('utf-8'))
        return hasher.hexdigest()
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate a secure random token."""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password with salt."""
        try:
            import bcrypt
            return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        except ImportError:
            # Fallback to simple hash if bcrypt not available
            salt = secrets.token_hex(16)
            return f"simple:{salt}:{hashlib.sha256((salt + password).encode()).hexdigest()}"

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify a password against hash."""
        try:
            if hashed.startswith("simple:"):
                _, salt, hash_value = hashed.split(":", 2)
                return hashlib.sha256((salt + password).encode()).hexdigest() == hash_value
            else:
                import bcrypt
                return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except (ImportError, ValueError):
            return False


class JsonUtils:
    """JSON utility functions."""
    
    @staticmethod
    def safe_loads(text: str, default: Any = None) -> Any:
        """Safely load JSON with fallback."""
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return default
    
    @staticmethod
    def safe_dumps(obj: Any, default: str = "{}") -> str:
        """Safely dump JSON with fallback."""
        try:
            return json.dumps(obj, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            return default


class FileUtils:
    """File utility functions."""
    
    @staticmethod
    def ensure_dir(path: Union[str, Path]) -> Path:
        """Ensure directory exists."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    @staticmethod
    def safe_read(path: Union[str, Path], default: str = "") -> str:
        """Safely read file with fallback."""
        try:
            return Path(path).read_text(encoding='utf-8')
        except (FileNotFoundError, PermissionError, UnicodeDecodeError):
            return default
    
    @staticmethod
    def safe_write(path: Union[str, Path], content: str) -> bool:
        """Safely write file."""
        try:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8')
            return True
        except (PermissionError, OSError):
            return False
    
    @staticmethod
    def format_bytes(bytes_count: int) -> str:
        """Format bytes in human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f}{unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f}PB"


class ValidationUtils:
    """Validation utility functions."""
    
    @staticmethod
    def safe_int(value: Any, default: int = 0) -> int:
        """Safely convert to int."""
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
    
    @staticmethod
    def safe_float(value: Any, default: float = 0.0) -> float:
        """Safely convert to float."""
        try:
            return float(value)
        except (ValueError, TypeError):
            return default
    
    @staticmethod
    def safe_bool(value: Any, default: bool = False) -> bool:
        """Safely convert to bool."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        return bool(value) if value is not None else default
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Basic email validation."""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))


# Global utility instances
string_utils = StringUtils()
datetime_utils = DateTimeUtils()
hash_utils = HashUtils()
json_utils = JsonUtils()
file_utils = FileUtils()
validation_utils = ValidationUtils()

# Convenience functions
generate_id = StringUtils.generate_id
current_timestamp = DateTimeUtils.current_timestamp
format_bytes = FileUtils.format_bytes
safe_int = ValidationUtils.safe_int
safe_float = ValidationUtils.safe_float
safe_bool = ValidationUtils.safe_bool

__all__ = [
    "StringUtils", "DateTimeUtils", "HashUtils", "JsonUtils", "FileUtils", "ValidationUtils",
    "string_utils", "datetime_utils", "hash_utils", "json_utils", "file_utils", "validation_utils",
    "generate_id", "current_timestamp", "format_bytes", "safe_int", "safe_float", "safe_bool"
]
