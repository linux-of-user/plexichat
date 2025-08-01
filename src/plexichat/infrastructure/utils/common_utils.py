# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import hashlib
import logging
import re
import secrets
import string
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

class ValidationUtils:
    """Common validation utilities."""

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    @staticmethod
    def validate_username(username: str, min_length: int = 3, max_length: int = 20) -> Dict[str, Any]:
        """Validate username format."""
        errors = []

        if len(username) < min_length:
            errors.append(f"Username must be at least {min_length} characters")
        elif len(username) > max_length:
            errors.append(f"Username must be no more than {max_length} characters")

        if not username.replace('_', '').replace('-', '').isalnum():
            errors.append("Username can only contain letters, numbers, underscores, and hyphens")

        if username.startswith('-') or username.endswith('-'):
            errors.append("Username cannot start or end with a hyphen")

        return {
            "valid": len(errors) == 0,
            "errors": errors
        }

    @staticmethod
    def validate_password(password: str, min_length: int = 8) -> Dict[str, Any]:
        """Validate password strength."""
        errors = []

        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters")

        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")

        if not any(c in string.punctuation for c in password):
            errors.append("Password must contain at least one special character")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "strength": "strong" if len(errors) == 0 else "weak"
        }

class SecurityUtils:
    """Common security utilities."""

    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate secure random token."""
        return secrets.token_urlsafe(length)

    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
        """Hash password with salt."""
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

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against hash."""
        # This is a simplified version - in production use proper password hashing
        return hashlib.sha256(password.encode()).hexdigest() == hashed

    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 1000) -> str:
        """Sanitize user input."""
        if not input_str:
            return ""

        # Remove null bytes and control characters
        sanitized = ''.join(char for char in input_str if ord(char) >= 32)

        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]

        return sanitized.strip()

    @staticmethod
    def generate_csrf_token() -> str:
        """Generate CSRF token."""
        return secrets.token_hex(32)

class DateTimeUtils:
    """Common datetime utilities."""

    @staticmethod
    def now_iso() -> str:
        """Get current datetime in ISO format."""
        return datetime.now().isoformat()

    @staticmethod
    def parse_iso(iso_string: str) -> Optional[datetime]:
        """Parse ISO datetime string."""
        try:
            return datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def format_relative_time(dt: datetime) -> str:
        """Format datetime as relative time (e.g., '2 hours ago')."""
        now = datetime.now()
        if dt.tzinfo is not None:
            now = now.replace(tzinfo=dt.tzinfo)

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
    def is_expired(dt: datetime, ttl_seconds: int) -> bool:
        """Check if datetime is expired based on TTL."""
        now = datetime.now()
        if dt.tzinfo is not None:
            now = now.replace(tzinfo=dt.tzinfo)

        return (now - dt).total_seconds() > ttl_seconds

class FileUtils:
    """Common file utilities."""

    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> Path:
        """Ensure directory exists."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def safe_filename(filename: str) -> str:
        """Create safe filename by removing/replacing invalid characters."""
        # Remove invalid characters
        safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)

        # Remove leading/trailing dots and spaces
        safe_name = safe_name.strip('. ')

        # Limit length
        if len(safe_name) > 255:
            name, ext = safe_name.rsplit('.', 1) if '.' in safe_name else (safe_name, '')
            safe_name = name[:255-len(ext)-1] + ('.' + ext if ext else '')

        return safe_name or 'unnamed'

    @staticmethod
    def get_file_hash(file_path: Union[str, Path], algorithm: str = 'md5') -> str:
        """Get file hash."""
        hash_func = getattr(hashlib, algorithm)()

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)

        return hash_func.hexdigest()

    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Format file size in human readable format."""
        if size_bytes == 0:
            return "0 B"

        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1

        return f"{size_bytes:.1f} {size_names[i]}"

class ResponseUtils:
    """Common API response utilities."""

    @staticmethod
    def success_response(data: Optional[Any] = None, message: str = "Success") -> Dict[str, Any]:
        """Create success response."""
        response = {
            "success": True,
            "message": message,
            "timestamp": DateTimeUtils.now_iso()
        }

        if data is not None:
            response["data"] = data

        return response

    @staticmethod
    def error_response(message: str, error_code: Optional[str] = None, details: Optional[Any] = None) -> Dict[str, Any]:
        """Create error response."""
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

    @staticmethod
    def paginated_response(data: List[Any], page: int, per_page: int, total: int, message: str = "Success") -> Dict[str, Any]:
        """Create paginated response."""
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

class LoggingUtils:
    """Common logging utilities."""

    @staticmethod
    def setup_logger(name: str, level: str = "INFO", format_string: Optional[str] = None) -> logging.Logger:
        """Setup logger with common configuration."""
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level.upper()))

        if not logger.handlers:
            handler = logging.StreamHandler()

            if format_string is None:
                format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

            formatter = logging.Formatter(format_string)
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    @staticmethod
    def log_performance(func_name: str, duration: float, logger: Optional[logging.Logger] = None):
        """Log performance metrics."""
        if logger is None:
            logger = logging.getLogger(__name__)

        if duration > 1.0:
            logger.warning(f"Slow operation: {func_name} took {duration:.2f}s")
        else:
            logger.debug(f"Performance: {func_name} took {duration:.3f}s")

class AsyncUtils:
    """Common async utilities."""

    @staticmethod
    async def run_with_timeout(coro, timeout: float):
        """Run coroutine with timeout."""
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Operation timed out after {timeout}s")
            raise

    @staticmethod
    async def retry_async(coro_func: Callable, max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0):
        """Retry async function with exponential backoff."""
        last_exception = None

        for attempt in range(max_retries):
            try:
                return await coro_func()
            except Exception as e:
                last_exception = e
                if attempt < max_retries - 1:
                    await asyncio.sleep(delay * (backoff ** attempt))

        raise last_exception

    @staticmethod
    async def gather_with_concurrency(tasks: List, max_concurrent: int = 10):
        """Gather tasks with concurrency limit."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def controlled_task(task):
            async with semaphore:
                return await task

        return await asyncio.gather(*[controlled_task(task) for task in tasks])

def monitor_performance(logger: Optional[logging.Logger] = None):
    """Decorator to monitor function performance."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = datetime.now()
            try:
                result = func(*args, **kwargs)
                duration = (datetime.now() - start_time).total_seconds()
                LoggingUtils.log_performance(func.__name__, duration, logger)
                return result
            except Exception:
                duration = (datetime.now() - start_time).total_seconds()
                LoggingUtils.log_performance(f"{func.__name__} (error)", duration, logger)
                raise

        async def async_wrapper(*args, **kwargs):
            start_time = datetime.now()
            try:
                result = await func(*args, **kwargs)
                duration = (datetime.now() - start_time).total_seconds()
                LoggingUtils.log_performance(func.__name__, duration, logger)
                return result
            except Exception:
                duration = (datetime.now() - start_time).total_seconds()
                LoggingUtils.log_performance(f"{func.__name__} (error)", duration, logger)
                raise

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper
    return decorator
