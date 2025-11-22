"""
PlexiChat Core Utilities
Consolidated utility functions for the entire application.
"""

import hashlib
import json
import logging
import re
import secrets
import time
import unicodedata
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    Union,
)

logger = logging.getLogger(__name__)

# Security-oriented constants
MAX_FILENAME_LENGTH = 120
SAFE_FILENAME_REPLACEMENT = "_"
DEFAULT_ALLOWED_EXTENSIONS: Set[str] = {
    ".txt",
    ".md",
    ".json",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".pdf",
}

T = TypeVar("T")


class StringUtils:
    """String utility functions."""

    @staticmethod
    def generate_id(prefix: str = "") -> str:
        """Generate a unique ID."""
        return f"{prefix}{uuid.uuid4().hex[:8]}" if prefix else uuid.uuid4().hex[:12]

    @staticmethod
    def sanitize_string(text: Any, max_length: int = 255) -> str:
        """Sanitize and truncate string.

        - Converts non-str to str
        - Removes control characters (below ord 32)
        - Truncates to max_length
        """
        if not isinstance(text, str):
            text = str(text)
        # Normalize unicode to NFC to avoid tricky characters
        text = unicodedata.normalize("NFC", text)
        # Remove control characters and limit length
        sanitized = "".join(char for char in text if ord(char) >= 32)
        return sanitized[:max_length]

    @staticmethod
    def safe_filename(filename: str, max_length: int = 255) -> str:
        """Create a safe filename by replacing unsafe characters.

        This is a general-purpose safe filename helper; more strict validation
        and policy enforcement uses sanitize_filename / validate_filename below.
        """
        # Normalize unicode
        filename = unicodedata.normalize("NFC", str(filename))
        # Remove path separators and other unsafe characters
        safe = re.sub(r'[<>:"/\\|?*\n\r\t\0]', SAFE_FILENAME_REPLACEMENT, filename)
        # Collapse repeats of replacement
        rep = re.escape(SAFE_FILENAME_REPLACEMENT)
        safe = re.sub(rf"{rep}+", SAFE_FILENAME_REPLACEMENT, safe)
        # Strip leading/trailing dots and spaces
        safe = safe.strip(" .")
        return safe[:max_length] if max_length and len(safe) > max_length else safe

    @staticmethod
    def sanitize_filename(
        filename: str,
        max_length: int = MAX_FILENAME_LENGTH,
        replace_char: str = SAFE_FILENAME_REPLACEMENT,
    ) -> str:
        """Sanitize filename to enforce safe characters and max length.

        - Removes path elements
        - Normalizes unicode
        - Replaces unsafe characters with replace_char
        - Ensures filename length is limited
        """
        if not filename:
            return ""
        name = str(filename)
        # Strip any directory components to avoid path traversal by name parts
        name = Path(name).name
        name = unicodedata.normalize("NFC", name)
        # Replace NULs and control chars
        name = "".join(ch if ord(ch) >= 32 else replace_char for ch in name)
        # Replace characters commonly unsafe for filenames
        name = re.sub(r'[<>:"/\\|?*\n\r\t]', replace_char, name)
        # Collapse multiple replacements
        rep = re.escape(replace_char)
        name = re.sub(rf"{rep}+", replace_char, name)
        # Remove leading/trailing separators and dots
        name = name.strip(" .")
        if max_length and len(name) > max_length:
            # Preserve extension if present
            stem = name
            suffix = ""
            p = Path(name)
            if p.suffix:
                suffix = p.suffix
                stem = p.stem
            allowed_stem_len = max(1, max_length - len(suffix))
            stem = stem[:allowed_stem_len]
            name = f"{stem}{suffix}"
        return name

    @staticmethod
    def validate_filename(
        filename: str,
        allowed_extensions: Optional[Iterable[str]] = None,
        max_length: int = MAX_FILENAME_LENGTH,
    ) -> Tuple[bool, Optional[str]]:
        """Validate filename against common security rules.

        Returns (True, None) if valid, otherwise (False, "reason").
        """
        if not filename:
            return False, "empty filename"
        if any(ch in filename for ch in ("/", "\\", "\x00")):
            return False, "filename contains path separators or null bytes"
        # Prevent path traversal
        if ".." in filename or filename.startswith(("/", "\\")):
            return False, "filename appears to contain path traversal"
        if len(filename) > max_length:
            return False, f"filename exceeds maximum length of {max_length}"
        p = Path(filename)
        if p.name != filename:
            return False, "filename contains directory components"
        suffix = p.suffix.lower()
        if allowed_extensions:
            allowed = {
                s.lower() if s.startswith(".") else f".{s.lower()}"
                for s in allowed_extensions
            }
            if suffix not in allowed:
                return False, f"extension '{suffix}' not allowed"
        return True, None

    @staticmethod
    def truncate(text: str, length: int = 100, ellipsis: str = "...") -> str:
        """Truncate text to a given length preserving whole characters."""
        if not isinstance(text, str):
            text = str(text)
        if length <= 0:
            return ""
        if len(text) <= length:
            return text
        return text[: max(0, length - len(ellipsis))] + ellipsis

    @staticmethod
    def to_snake_case(value: str) -> str:
        """Convert string to snake_case."""
        value = unicodedata.normalize("NFKD", str(value))
        value = re.sub(r"[^\w\s-]", "", value).strip().lower()
        return re.sub(r"[\s\-]+", "_", value)

    @staticmethod
    def to_camel_case(value: str) -> str:
        """Convert string to camelCase."""
        parts = StringUtils.to_snake_case(value).split("_")
        if not parts:
            return ""
        return parts[0] + "".join(p.capitalize() for p in parts[1:] if p)


class DateTimeUtils:
    """DateTime utility functions."""

    @staticmethod
    def current_timestamp() -> str:
        """Get current timestamp as ISO string."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def now() -> datetime:
        """Return current datetime with UTC tzinfo."""
        return datetime.now(timezone.utc)

    @staticmethod
    def timestamp_to_datetime(timestamp: Union[str, float, int]) -> datetime:
        """Convert timestamp to datetime.

        Accepts ISO strings or Unix timestamps.
        """
        if isinstance(timestamp, str):
            # Handle trailing Z
            try:
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                # Try common fallbacks
                try:
                    # Attempt parsing as float string (unix)
                    return datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
                except Exception:
                    from plexichat.core.exceptions import ValidationError, ErrorCode
                    raise ValidationError(
                        f"Unrecognized timestamp format: {timestamp}",
                        ErrorCode.VALIDATION_INVALID_FORMAT,
                        field="timestamp",
                        value=timestamp
                    )
        return datetime.fromtimestamp(float(timestamp), tz=timezone.utc)

    @staticmethod
    def datetime_to_timestamp(dt: datetime) -> float:
        """Convert datetime to Unix timestamp (seconds as float)."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()

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

    @staticmethod
    def time_ago(dt: datetime, default: str = "just now") -> str:
        """Return human-readable time difference between now and dt."""
        now = DateTimeUtils.now()
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        diff = now - dt
        seconds = diff.total_seconds()
        if seconds < 10:
            return default
        if seconds < 60:
            return f"{int(seconds)}s ago"
        if seconds < 3600:
            return f"{int(seconds // 60)}m ago"
        if seconds < 86400:
            return f"{int(seconds // 3600)}h ago"
        days = int(seconds // 86400)
        return f"{days}d ago"


class HashUtils:
    """Hashing utility functions."""

    @staticmethod
    def hash_string(text: str, algorithm: str = "sha256") -> str:
        """Hash a string."""
        hasher = hashlib.new(algorithm)
        hasher.update(text.encode("utf-8"))
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

            return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
                "utf-8"
            )
        except Exception:
            # Fallback to simple hash if bcrypt not available
            salt = secrets.token_hex(16)
            return f"simple:{salt}:{hashlib.sha256((salt + password).encode()).hexdigest()}"

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify a password against hash."""
        try:
            if hashed.startswith("simple:"):
                _, salt, hash_value = hashed.split(":", 2)
                return (
                    hashlib.sha256((salt + password).encode()).hexdigest() == hash_value
                )
            else:
                import bcrypt

                return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        except Exception:
            return False


class JsonUtils:
    """JSON utility functions."""

    @staticmethod
    def safe_loads(text: Union[str, bytes], default: Any = None) -> Any:
        """Safely load JSON with fallback."""
        try:
            if isinstance(text, bytes):
                text = text.decode("utf-8")
            return json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError):
            return default

    @staticmethod
    def safe_dumps(obj: Any, default: str = "{}") -> str:
        """Safely dump JSON with fallback."""
        try:
            return json.dumps(obj, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            try:
                return json.dumps(str(obj))
            except Exception:
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
            return Path(path).read_text(encoding="utf-8")
        except (FileNotFoundError, PermissionError, UnicodeDecodeError):
            return default

    @staticmethod
    def safe_write(path: Union[str, Path], content: str) -> bool:
        """Safely write file."""
        try:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            return True
        except (PermissionError, OSError):
            return False

    @staticmethod
    def format_bytes(bytes_count: int) -> str:
        """Format bytes in human readable format."""
        size = float(bytes_count)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                return f"{size:.1f}{unit}"
            size /= 1024.0
        return f"{size:.1f}PB"

    @staticmethod
    def write_atomic(path: Union[str, Path], content: str) -> bool:
        """Attempt an atomic write to avoid partial files.

        Writes to a temporary file then renames.
        """
        p = Path(path)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_name(f".{p.name}.{uuid.uuid4().hex}.tmp")
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(p)
            return True
        except Exception:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass
            return False


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
            return value.lower() in ("true", "1", "yes", "on")
        return bool(value) if value is not None else default

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Basic email validation."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, str(email)))

    @staticmethod
    def ensure_list(value: Any) -> List[Any]:
        """Ensure the value is a list; wrap singletons."""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, (set, tuple)):
            return list(value)
        return [value]

    @staticmethod
    def ensure_set(value: Any) -> Set[Any]:
        """Ensure the value is a set."""
        if value is None:
            return set()
        if isinstance(value, set):
            return value
        if isinstance(value, (list, tuple)):
            return set(value)
        return {value}

    @staticmethod
    def safe_get(d: Dict[str, Any], path: Sequence[str], default: Any = None) -> Any:
        """Safely get a nested value from dict by path."""
        cur: Any = d
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                return default
            cur = cur[key]
        return cur


# Error handling utilities and exceptions
class ValidationError(Exception):
    """Generic validation error."""

    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.code = code

    def to_dict(self) -> Dict[str, Any]:
        return {"error": self.message, "code": self.code}


class FileValidationError(ValidationError):
    """File validation specific error."""

    def __init__(self, message: str, code: Optional[str] = "file_invalid"):
        super().__init__(message, code=code)


def format_error(exc: Exception, include_type: bool = False) -> Dict[str, Any]:
    """Format exception into a serializable dict for responses/logging."""
    data: Dict[str, Any] = {"message": getattr(exc, "message", str(exc))}
    if include_type:
        data["type"] = exc.__class__.__name__
    # attach code when present
    code = getattr(exc, "code", None)
    if code:
        data["code"] = code
    return data


# Simple timing utilities for performance logging
@contextmanager
def timed_operation(name: str, level: int = logging.DEBUG) -> Iterator[None]:
    """Context manager to time an operation and log its duration."""
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        logger.log(
            level,
            "Operation '%s' completed in %s",
            name,
            DateTimeUtils.format_duration(elapsed),
        )


def timeit(func: Callable[..., T]) -> Callable[..., T]:
    """Decorator to measure function execution time and log it."""

    def wrapper(*args: Any, **kwargs: Any) -> T:
        start = time.perf_counter()
        try:
            return func(*args, **kwargs)
        finally:
            elapsed = time.perf_counter() - start
            logger.debug(
                "Function %s finished in %s",
                func.__name__,
                DateTimeUtils.format_duration(elapsed),
            )

    wrapper.__name__ = getattr(func, "__name__", "wrapped")
    return wrapper


# Generic helpers
def safe_cast(
    value: Any, to_type: Callable[[Any], T], default: Optional[T] = None
) -> Optional[T]:
    """Attempt to cast value to target type, return default on failure."""
    try:
        return to_type(value)
    except Exception:
        return default


def deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge dict b into a and return result (new dict)."""
    result = dict(a)
    for key, val in b.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def chunked_iterable(iterable: Iterable[T], size: int) -> Iterable[List[T]]:
    """Yield chunks of an iterable of given size."""
    chunk: List[T] = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


# Global utility instances
string_utils = StringUtils()
datetime_utils = DateTimeUtils()
hash_utils = HashUtils()
json_utils = JsonUtils()
file_utils = FileUtils()
validation_utils = ValidationUtils()

# Convenience functions (backwards-compatible)
generate_id = StringUtils.generate_id
current_timestamp = DateTimeUtils.current_timestamp
format_bytes = FileUtils.format_bytes
safe_int = ValidationUtils.safe_int
safe_float = ValidationUtils.safe_float
safe_bool = ValidationUtils.safe_bool
sanitize_filename = StringUtils.sanitize_filename
validate_filename = StringUtils.validate_filename
safe_filename = StringUtils.safe_filename
truncate = StringUtils.truncate
to_snake_case = StringUtils.to_snake_case
to_camel_case = StringUtils.to_camel_case
timestamp_to_datetime = DateTimeUtils.timestamp_to_datetime
datetime_to_timestamp = DateTimeUtils.datetime_to_timestamp
time_ago = DateTimeUtils.time_ago
format_error_dict = format_error
ensure_list = ValidationUtils.ensure_list
ensure_set = ValidationUtils.ensure_set
safe_get = ValidationUtils.safe_get
safe_cast_fn = safe_cast
deep_merge_dicts = deep_merge
timed = timed_operation
timeit_decorator = timeit

__all__ = [
    "StringUtils",
    "DateTimeUtils",
    "HashUtils",
    "JsonUtils",
    "FileUtils",
    "ValidationUtils",
    "string_utils",
    "datetime_utils",
    "hash_utils",
    "json_utils",
    "file_utils",
    "validation_utils",
    "generate_id",
    "current_timestamp",
    "format_bytes",
    "safe_int",
    "safe_float",
    "safe_bool",
    "sanitize_filename",
    "validate_filename",
    "safe_filename",
    "truncate",
    "to_snake_case",
    "to_camel_case",
    "timestamp_to_datetime",
    "datetime_to_timestamp",
    "time_ago",
    "format_error_dict",
    "ensure_list",
    "ensure_set",
    "safe_get",
    "safe_cast_fn",
    "deep_merge_dicts",
    "timed",
    "timeit_decorator",
    "ValidationError",
    "FileValidationError",
    "MAX_FILENAME_LENGTH",
    "DEFAULT_ALLOWED_EXTENSIONS",
]
