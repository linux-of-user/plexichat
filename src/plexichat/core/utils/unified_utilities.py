"""
import string
PlexiChat Unified Utilities - SINGLE SOURCE OF TRUTH

Consolidates ALL utility functionality from:
- core/utils/helpers.py - INTEGRATED
- infrastructure/utils/common_utils.py - INTEGRATED
- infrastructure/utils/helpers_optimized.py - INTEGRATED
- All other utility modules - INTEGRATED

Provides a single, unified interface for all utility operations.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union
from enum import Enum
from dataclasses import dataclass
import threading

logger = logging.getLogger(__name__)


class StringUtils:
    """String utility functions - UNIFIED."""

    @staticmethod
    def is_empty(value: Optional[str]) -> bool:
        """Check if string is empty or None."""
        return not value or not value.strip()

    @staticmethod
    def truncate(text: str, max_length: int, suffix: str = "...") -> str:
        """Truncate string to max length."""
        try:
            if len(text) <= max_length:
                return text
            return text[:max_length - len(suffix)] + suffix
        except Exception as e:
            logger.error(f"Error truncating string: {e}")
            return text

    @staticmethod
    def sanitize(text: str, allow_html: bool = False) -> str:
        """Sanitize string for safe use."""
        try:
            if not text:
                return ""

            # Remove null bytes
            text = text.replace('\x00', '')

            if not allow_html:
                # Basic HTML encoding
                text = text.replace('&', '&amp;')
                text = text.replace('<', '&lt;')
                text = text.replace('>', '&gt;')
                text = text.replace('"', '&quot;')
                text = text.replace("'", '&#x27;')

            return text.strip()

        except Exception as e:
            logger.error(f"Error sanitizing string: {e}")
            return str(text) if text else ""

    @staticmethod
    def to_snake_case(text: str) -> str:
        """Convert string to snake_case."""
        try:
            # Insert underscore before uppercase letters
            s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', text)
            # Insert underscore before uppercase letters preceded by lowercase
            s2 = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1)
            return s2.lower()
        except Exception as e:
            logger.error(f"Error converting to snake_case: {e}")
            return text.lower()

    @staticmethod
    def to_camel_case(text: str) -> str:
        """Convert string to camelCase."""
        try:
            components = text.split('_')
            return components[0] + ''.join(word.capitalize() for word in components[1:])
        except Exception as e:
            logger.error(f"Error converting to camelCase: {e}")
            return text

    @staticmethod
    def generate_slug(text: str, max_length: int = 50) -> str:
        """Generate URL-friendly slug."""
        try:
            # Convert to lowercase and replace spaces/special chars with hyphens
            slug = re.sub(r'[^\w\s-]', '', text.lower())
            slug = re.sub(r'[-\s]+', '-', slug)
            slug = slug.strip('-')

            # Truncate if needed
            if len(slug) > max_length:
                slug = slug[:max_length].rstrip('-')

            return slug or 'unnamed'

        except Exception as e:
            logger.error(f"Error generating slug: {e}")
            return 'unnamed'

    @staticmethod
    def mask_sensitive(text: str, visible_chars: int = 4, mask_char: str = "*") -> str:
        """Mask sensitive information."""
        try:
            if len(text) <= visible_chars:
                return mask_char * len(text)

            visible_start = visible_chars // 2
            visible_end = visible_chars - visible_start

            masked_length = len(text) - visible_chars
            mask = mask_char * min(masked_length, 8)  # Limit mask length

            return text[:visible_start] + mask + text[-visible_end:] if visible_end > 0 else text[:visible_start] + mask

        except Exception as e:
            logger.error(f"Error masking string: {e}")
            return mask_char * 8


class DateTimeUtils:
    """Date and time utility functions - UNIFIED."""

    @staticmethod
    def now_utc() -> datetime:
        """Get current UTC datetime."""
        return datetime.now(timezone.utc)

    @staticmethod
    def now_iso() -> str:
        """Get current UTC datetime as ISO string."""
        return DateTimeUtils.now_utc().isoformat()

    @staticmethod
    def timestamp() -> int:
        """Get current timestamp."""
        return int(time.time())

    @staticmethod
    def from_timestamp(timestamp: Union[int, float]) -> datetime:
        """Convert timestamp to datetime."""
        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except Exception as e:
            logger.error(f"Error converting timestamp: {e}")
            return DateTimeUtils.now_utc()

    @staticmethod
    def to_timestamp(dt: datetime) -> int:
        """Convert datetime to timestamp."""
        try:
            return int(dt.timestamp())
        except Exception as e:
            logger.error(f"Error converting to timestamp: {e}")
            return DateTimeUtils.timestamp()

    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in human readable format."""
        try:
            if seconds < 60:
                return f"{seconds:.1f}s"
            elif seconds < 3600:
                minutes = seconds / 60
                return f"{minutes:.1f}m"
            elif seconds < 86400:
                hours = seconds / 3600
                return f"{hours:.1f}h"
            else:
                days = seconds / 86400
                return f"{days:.1f}d"
        except Exception as e:
            logger.error(f"Error formatting duration: {e}")
            return f"{seconds}s"

    @staticmethod
    def parse_iso(iso_string: str) -> Optional[datetime]:
        """Parse ISO datetime string."""
        try:
            return datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
        except Exception as e:
            logger.error(f"Error parsing ISO string: {e}")
            return None

    @staticmethod
    def age_in_seconds(dt: datetime) -> float:
        """Get age of datetime in seconds."""
        try:
            return (DateTimeUtils.now_utc() - dt).total_seconds()
        except Exception as e:
            logger.error(f"Error calculating age: {e}")
            return 0.0


class HashUtils:
    """Hash and cryptographic utility functions - UNIFIED."""

    @staticmethod
    def sha256(data: Union[str, bytes]) -> str:
        """Generate SHA-256 hash."""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            return hashlib.sha256(data).hexdigest()
        except Exception as e:
            logger.error(f"Error generating SHA-256: {e}")
            return ""

    @staticmethod
    def md5(data: Union[str, bytes]) -> str:
        """Generate MD5 hash."""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            return hashlib.md5(data).hexdigest()
        except Exception as e:
            logger.error(f"Error generating MD5: {e}")
            return ""

    @staticmethod
    def hmac_sha256(data: Union[str, bytes], key: Union[str, bytes]) -> str:
        """Generate HMAC-SHA256."""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            if isinstance(key, str):
                key = key.encode('utf-8')
            return hmac.new(key, data, hashlib.sha256).hexdigest()
        except Exception as e:
            logger.error(f"Error generating HMAC-SHA256: {e}")
            return ""

    @staticmethod
    def generate_salt(length: int = 32) -> str:
        """Generate random salt."""
        try:
            return secrets.token_hex(length)
        except Exception as e:
            logger.error(f"Error generating salt: {e}")
            return "default_salt"

    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
        """Secure string comparison to prevent timing attacks."""
        try:
            return hmac.compare_digest(a, b)
        except Exception as e:
            logger.error(f"Error in secure compare: {e}")
            return False


class JsonUtils:
    """JSON utility functions - UNIFIED."""

    @staticmethod
    def safe_loads(json_str: str, default: Any = None) -> Any:
        """Safely parse JSON string."""
        try:
            return json.loads(json_str)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Error parsing JSON: {e}")
            return default

    @staticmethod
    def safe_dumps(data: Any, default: Any = None, indent: Optional[int] = None) -> str:
        """Safely serialize to JSON string."""
        try:
            return json.dumps(data, default=str, indent=indent, ensure_ascii=False)
        except (TypeError, ValueError) as e:
            logger.error(f"Error serializing JSON: {e}")
            return json.dumps(default) if default is not None else "{}"

    @staticmethod
    def pretty_print(data: Any) -> str:
        """Pretty print JSON data."""
        return JsonUtils.safe_dumps(data, indent=2)

    @staticmethod
    def minify(json_str: str) -> str:
        """Minify JSON string."""
        try:
            data = json.loads(json_str)
            return json.dumps(data, separators=(',', ':'))
        except Exception as e:
            logger.error(f"Error minifying JSON: {e}")
            return json_str

    @staticmethod
    def merge_objects(*objects: Dict[str, Any]) -> Dict[str, Any]:
        """Merge multiple JSON objects."""
        try:
            result = {}
            for obj in objects:
                if isinstance(obj, dict):
                    result.update(obj)
            return result
        except Exception as e:
            logger.error(f"Error merging JSON objects: {e}")
            return {}


class ListUtils:
    """List utility functions - UNIFIED."""

    @staticmethod
    def chunk(lst: List[Any], chunk_size: int) -> List[List[Any]]:
        """Split list into chunks."""
        try:
            return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
        except Exception as e:
            logger.error(f"Error chunking list: {e}")
            return [lst] if lst else []

    @staticmethod
    def deduplicate(lst: List[Any], key: Optional[Callable] = None) -> List[Any]:
        """Remove duplicates from list."""
        try:
            if key is None:
                return list(dict.fromkeys(lst))
            else:
                seen = set()
                result = []
                for item in lst:
                    item_key = key(item)
                    if item_key not in seen:
                        seen.add(item_key)
                        result.append(item)
                return result
        except Exception as e:
            logger.error(f"Error deduplicating list: {e}")
            return lst

    @staticmethod
    def flatten(nested_list: List[Any]) -> List[Any]:
        """Flatten nested list."""
        try:
            result = []
            for item in nested_list:
                if isinstance(item, list):
                    result.extend(ListUtils.flatten(item))
                else:
                    result.append(item)
            return result
        except Exception as e:
            logger.error(f"Error flattening list: {e}")
            return nested_list

    @staticmethod
    def safe_get(lst: List[Any], index: int, default: Any = None) -> Any:
        """Safely get item from list by index."""
        try:
            return lst[index] if 0 <= index < len(lst) else default
        except Exception:
            return default

    @staticmethod
    def batch_process(lst: List[Any], batch_size: int, ):
                     processor: Callable[[List[Any]], Any]) -> List[Any]:
        """Process list in batches."""
        try:
            results = []
            for chunk in ListUtils.chunk(lst, batch_size):
                result = processor(chunk)
                if result is not None:
                    results.append(result)
            return results
        except Exception as e:
            logger.error(f"Error in batch processing: {e}")
            return []


class DictUtils:
    """Dictionary utility functions - UNIFIED."""

    @staticmethod
    def safe_get(data: Dict[str, Any], key: str, default: Any = None) -> Any:
        """Safely get value from dictionary."""
        try:
            return data.get(key, default)
        except Exception:
            return default

    @staticmethod
    def deep_get(data: Dict[str, Any], key_path: str, separator: str = ".", default: Any = None) -> Any:
        """Get value from nested dictionary using dot notation."""
        try:
            keys = key_path.split(separator)
            value = data

            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return default

            return value
        except Exception as e:
            logger.error(f"Error getting deep value: {e}")
            return default

    @staticmethod
    def deep_set(data: Dict[str, Any], key_path: str, value: Any, separator: str = ".") -> Dict[str, Any]:
        """Set value in nested dictionary using dot notation."""
        try:
            keys = key_path.split(separator)
            current = data

            for key in keys[:-1]:
                if key not in current or not isinstance(current[key], dict):
                    current[key] = {}
                current = current[key]

            current[keys[-1]] = value
            return data
        except Exception as e:
            logger.error(f"Error setting deep value: {e}")
            return data

    @staticmethod
    def merge(*dicts: Dict[str, Any]) -> Dict[str, Any]:
        """Merge multiple dictionaries."""
        try:
            result = {}
            for d in dicts:
                if isinstance(d, dict):
                    result.update(d)
            return result
        except Exception as e:
            logger.error(f"Error merging dictionaries: {e}")
            return {}

    @staticmethod
    def filter_keys(data: Dict[str, Any], allowed_keys: List[str]) -> Dict[str, Any]:
        """Filter dictionary to only include allowed keys."""
        try:
            return {k: v for k, v in data.items() if k in allowed_keys}
        except Exception as e:
            logger.error(f"Error filtering keys: {e}")
            return {}

    @staticmethod
    def remove_none_values(data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove keys with None values."""
        try:
            return {k: v for k, v in data.items() if v is not None}
        except Exception as e:
            logger.error(f"Error removing None values: {e}")
            return data


class AsyncUtils:
    """Async utility functions - UNIFIED."""

    @staticmethod
    async def run_with_timeout(coro, timeout: float, default: Any = None) -> Any:
        """Run coroutine with timeout."""
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Operation timed out after {timeout} seconds")
            return default
        except Exception as e:
            logger.error(f"Error in async operation: {e}")
            return default

    @staticmethod
    async def retry_async(coro_func: Callable, max_retries: int = 3,)
                         delay: float = 1.0, backoff: float = 2.0) -> Any:
        """Retry async function with exponential backoff."""
        last_exception = None

        for attempt in range(max_retries):
            try:
                return await coro_func()
            except Exception as e:
                last_exception = e
                if attempt < max_retries - 1:
                    await asyncio.sleep(delay * (backoff ** attempt))
                    logger.warning(f"Retry {attempt + 1}/{max_retries} after error: {e}")

        logger.error(f"All {max_retries} attempts failed")
        raise last_exception

    @staticmethod
    async def gather_with_limit(coroutines: List[Callable], limit: int = 10) -> List[Any]:
        """Run coroutines with concurrency limit."""
        try:
            semaphore = asyncio.Semaphore(limit)

            async def limited_coro(coro):
                async with semaphore:
                    return await coro

            return await asyncio.gather(*[limited_coro(coro) for coro in coroutines])
        except Exception as e:
            logger.error(f"Error in limited gather: {e}")
            return []

    @staticmethod
    async def run_in_background(coro) -> asyncio.Task:
        """Run coroutine in background."""
        try:
            return asyncio.create_task(coro)
        except Exception as e:
            logger.error(f"Error creating background task: {e}")
            return None


class FileUtils:
    """File utility functions - UNIFIED."""

    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> Path:
        """Ensure directory exists."""
        try:
            path = Path(path)
            path.mkdir(parents=True, exist_ok=True)
            return path
        except Exception as e:
            logger.error(f"Error creating directory: {e}")
            return Path(path)

    @staticmethod
    def safe_filename(filename: str) -> str:
        """Create safe filename by removing/replacing invalid characters."""
        try:
            # Remove invalid characters
            safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)

            # Remove leading/trailing dots and spaces
            safe_name = safe_name.strip('. ')

            # Limit length
            if len(safe_name) > 255:
                name, ext = safe_name.rsplit('.', 1) if '.' in safe_name else (safe_name, '')
                safe_name = name[:255-len(ext)-1] + ('.' + ext if ext else '')

            return safe_name or 'unnamed'
        except Exception as e:
            logger.error(f"Error creating safe filename: {e}")
            return 'unnamed'

    @staticmethod
    def get_file_size(path: Union[str, Path]) -> int:
        """Get file size in bytes."""
        try:
            return Path(path).stat().st_size
        except Exception as e:
            logger.error(f"Error getting file size: {e}")
            return 0

    @staticmethod
    def format_bytes(bytes_value: int) -> str:
        """Format bytes to human readable string."""
        try:
            value = float(bytes_value)
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if value < 1024.0:
                    return f"{value:.1f} {unit}"
                value /= 1024.0
            return f"{value:.1f} PB"
        except Exception:
            return f"{bytes_value} B"

    @staticmethod
    def read_file_safe(path: Union[str, Path], encoding: str = 'utf-8') -> Optional[str]:
        """Safely read file content."""
        try:
            with open(path, 'r', encoding=encoding) as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file {path}: {e}")
            return None

    @staticmethod
    def write_file_safe(path: Union[str, Path], content: str, encoding: str = 'utf-8') -> bool:
        """Safely write file content."""
        try:
            # Ensure directory exists
            FileUtils.ensure_directory(Path(path).parent)

            with open(path, 'w', encoding=encoding) as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Error writing file {path}: {e}")
            return False


class SecurityUtils:
    """Security utility functions - UNIFIED."""

    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate secure random token."""
        try:
            return secrets.token_urlsafe(length)
        except Exception as e:
            logger.error(f"Error generating secure token: {e}")
            return "fallback_token"

    @staticmethod
    def generate_api_key(prefix: str = "pk", length: int = 32) -> str:
        """Generate API key with prefix."""
        try:
            token = secrets.token_urlsafe(length)
            return f"{prefix}_{token}"
        except Exception as e:
            logger.error(f"Error generating API key: {e}")
            return f"{prefix}_fallback_key"

    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
        """Hash password with salt."""
        try:
            if salt is None:
                salt = secrets.token_hex(16)

            # Combine password and salt
            combined = password + salt

            # Hash using SHA-256
            hashed = hashlib.sha256(combined.encode()).hexdigest()

            return {
                "hash": hashed,
                "salt": salt
            }
        except Exception as e:
            logger.error(f"Error hashing password: {e}")
            return {"hash": "", "salt": ""}

    @staticmethod
    def verify_password(password: str, hashed: str, salt: str) -> bool:
        """Verify password against hash."""
        try:
            combined = password + salt
            computed_hash = hashlib.sha256(combined.encode()).hexdigest()
            return hmac.compare_digest(hashed, computed_hash)
        except Exception as e:
            logger.error(f"Error verifying password: {e}")
            return False

    @staticmethod
    def sanitize_input(text: str, max_length: int = 1000) -> str:
        """Sanitize user input."""
        try:
            if not text:
                return ""

            # Truncate if too long
            if len(text) > max_length:
                text = text[:max_length]

            # Remove null bytes and control characters
            text = ''.join(char for char in text if ord(char) >= 32 or char in '\t\n\r')

            return text.strip()
        except Exception as e:
            logger.error(f"Error sanitizing input: {e}")
            return ""


class ValidationUtils:
    """Validation utility functions - UNIFIED."""

    @staticmethod
    def is_email(email: str) -> bool:
        """Validate email address."""
        try:
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return bool(re.match(pattern, email))
        except Exception as e:
            logger.error(f"Error validating email: {e}")
            return False

    @staticmethod
    def is_url(url: str) -> bool:
        """Validate URL."""
        try:
            pattern = r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'
            return bool(re.match(pattern, url))
        except Exception as e:
            logger.error(f"Error validating URL: {e}")
            return False

    @staticmethod
    def is_uuid(value: str) -> bool:
        """Validate UUID."""
        try:
            uuid.UUID(value)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def validate_password(password: str) -> Dict[str, Any]:
        """Validate password strength."""
        try:
            errors = []

            if len(password) < 8:
                errors.append("Password must be at least 8 characters long")

            if not re.search(r'[A-Z]', password):
                errors.append("Password must contain at least one uppercase letter")

            if not re.search(r'[a-z]', password):
                errors.append("Password must contain at least one lowercase letter")

            if not re.search(r'\d', password):
                errors.append("Password must contain at least one digit")

            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                errors.append("Password must contain at least one special character")

            return {
                "valid": len(errors) == 0,
                "errors": errors,
                "strength": "strong" if len(errors) == 0 else "weak"
            }
        except Exception as e:
            logger.error(f"Error validating password: {e}")
            return {"valid": False, "errors": ["Validation error"], "strength": "weak"}

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe use."""
        try:
            # Remove path separators and invalid characters
            safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)
            safe_name = safe_name.strip('. ')

            # Limit length
            if len(safe_name) > 255:
                name, ext = safe_name.rsplit('.', 1) if '.' in safe_name else (safe_name, '')
                safe_name = name[:255-len(ext)-1] + ('.' + ext if ext else '')

            return safe_name or 'unnamed'
        except Exception as e:
            logger.error(f"Error sanitizing filename: {e}")
            return 'unnamed'


class PerformanceUtils:
    """Performance utility functions - UNIFIED."""

    def __init__(self):
        self.timers: Dict[str, float] = {}
        self.counters: Dict[str, int] = {}
        self.lock = threading.Lock()

    def start_timer(self, name: str):
        """Start a performance timer."""
        try:
            with self.lock:
                self.timers[name] = time.time()
        except Exception as e:
            logger.error(f"Error starting timer {name}: {e}")

    def stop_timer(self, name: str) -> float:
        """Stop a performance timer and return duration."""
        try:
            with self.lock:
                if name in self.timers:
                    duration = time.time() - self.timers[name]
                    del self.timers[name]
                    return duration
                return 0.0
        except Exception as e:
            logger.error(f"Error stopping timer {name}: {e}")
            return 0.0

    def increment_counter(self, name: str, value: int = 1):
        """Increment a performance counter."""
        try:
            with self.lock:
                self.counters[name] = self.counters.get(name, 0) + value
        except Exception as e:
            logger.error(f"Error incrementing counter {name}: {e}")

    def get_counter(self, name: str) -> int:
        """Get counter value."""
        try:
            with self.lock:
                return self.counters.get(name, 0)
        except Exception as e:
            logger.error(f"Error getting counter {name}: {e}")
            return 0

    def reset_counters(self):
        """Reset all counters."""
        try:
            with self.lock:
                self.counters.clear()
        except Exception as e:
            logger.error(f"Error resetting counters: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        try:
            with self.lock:
                return {
                    "active_timers": list(self.timers.keys()),
                    "counters": self.counters.copy()
                }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {"active_timers": [], "counters": {}}


class ResponseUtils:
    """API response utility functions - UNIFIED."""

    @staticmethod
    def success_response(data: Optional[Any] = None, message: str = "Success") -> Dict[str, Any]:
        """Create success response."""
        try:
            response = {
                "success": True,
                "message": message,
                "timestamp": DateTimeUtils.now_iso()
            }

            if data is not None:
                response["data"] = data

            return response
        except Exception as e:
            logger.error(f"Error creating success response: {e}")
            return {"success": True, "message": "Success"}

    @staticmethod
    def error_response(message: str, error_code: Optional[str] = None,):
                      details: Optional[Any] = None) -> Dict[str, Any]:
        """Create error response."""
        try:
            response = {
                "success": False,
                "message": message,
                "timestamp": DateTimeUtils.now_iso()
            }

            if error_code:
                response["error_code"] = error_code

            if details:
                response["details"] = details

            return response
        except Exception as e:
            logger.error(f"Error creating error response: {e}")
            return {"success": False, "message": "Error"}

    @staticmethod
    def paginated_response(data: List[Any], page: int, per_page: int,):
                          total: int, message: str = "Success") -> Dict[str, Any]:
        """Create paginated response."""
        try:
            total_pages = (total + per_page - 1) // per_page

            return {
                "success": True,
                "message": message,
                "data": data,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1
                },
                "timestamp": DateTimeUtils.now_iso()
            }
        except Exception as e:
            logger.error(f"Error creating paginated response: {e}")
            return ResponseUtils.error_response("Pagination error")


# Convenience functions for backward compatibility
def generate_id() -> str:
    """Generate unique ID."""
    return str(uuid.uuid4())

def current_timestamp() -> int:
    """Get current timestamp."""
    return DateTimeUtils.timestamp()

def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable string."""
    return FileUtils.format_bytes(bytes_value)

def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to integer."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default

def safe_bool(value: Any, default: bool = False) -> bool:
    """Safely convert value to boolean."""
    try:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        return bool(value)
    except (ValueError, TypeError):
        return default

# Global performance utils instance
performance_utils = PerformanceUtils()

# Backward compatibility aliases
StringUtilities = StringUtils
DateTimeUtilities = DateTimeUtils
HashUtilities = HashUtils
JsonUtilities = JsonUtils
ListUtilities = ListUtils
DictUtilities = DictUtils
AsyncUtilities = AsyncUtils
FileUtilities = FileUtils
SecurityUtilities = SecurityUtils
ValidationUtilities = ValidationUtils
PerformanceUtilities = PerformanceUtils
ResponseUtilities = ResponseUtils

__all__ = [
    # Main utility classes
    'StringUtils',
    'DateTimeUtils',
    'HashUtils',
    'JsonUtils',
    'ListUtils',
    'DictUtils',
    'AsyncUtils',
    'FileUtils',
    'SecurityUtils',
    'ValidationUtils',
    'PerformanceUtils',
    'ResponseUtils',

    # Global instances
    'performance_utils',

    # Convenience functions
    'generate_id',
    'current_timestamp',
    'format_bytes',
    'safe_int',
    'safe_float',
    'safe_bool',

    # Backward compatibility aliases
    'StringUtilities',
    'DateTimeUtilities',
    'HashUtilities',
    'JsonUtilities',
    'ListUtilities',
    'DictUtilities',
    'AsyncUtilities',
    'FileUtilities',
    'SecurityUtilities',
    'ValidationUtilities',
    'PerformanceUtilities',
    'ResponseUtilities',
]
