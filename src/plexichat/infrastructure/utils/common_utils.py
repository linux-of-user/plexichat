import asyncio
import hashlib
import logging
import re
import secrets
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

import bcrypt

"""
Common Utilities
Shared utility functions to reduce code duplication across the codebase.
"""

logger = logging.getLogger("plexichat.utils.common")

class ValidationUtils:
    """Common validation utilities."""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_username(username: str, min_length: int = 3, max_length: int = 20) -> Dict[str, Any]:
        """Validate username with common rules."""
        if not username:
            return {"valid": False, "reason": "Username cannot be empty"}
        
        if len(username) < min_length:
            return {"valid": False, "reason": f"Username must be at least {min_length} characters"}
        
        if len(username) > max_length:
            return {"valid": False, "reason": f"Username cannot exceed {max_length} characters"}
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return {"valid": False, "reason": "Username can only contain letters, numbers, underscores, and hyphens"}
        
        if not re.match(r'^[a-zA-Z]', username):
            return {"valid": False, "reason": "Username must start with a letter"}
        
        return {"valid": True, "reason": "Username is valid"}
    
    @staticmethod
    def validate_password(password: str, min_length: int = 8) -> Dict[str, Any]:
        """Validate password strength."""
        if not password:
            return {"valid": False, "reason": "Password cannot be empty"}
        
        if len(password) < min_length:
            return {"valid": False, "reason": f"Password must be at least {min_length} characters"}
        
        checks = {
            "has_upper": bool(re.search(r'[A-Z]', password)),
            "has_lower": bool(re.search(r'[a-z]', password)),
            "has_digit": bool(re.search(r'\d', password)),
            "has_special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        
        strength_score = sum(checks.values())
        
        if strength_score < 3:
            return {
                "valid": False,
                "reason": "Password must contain at least 3 of: uppercase, lowercase, digits, special characters",
                "strength": "weak",
                "checks": checks
            }
        
        return {
            "valid": True,
            "reason": "Password is strong",
            "strength": "strong" if strength_score == 4 else "medium",
            "checks": checks
        }

class SecurityUtils:
    """Common security utilities."""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate secure random token."""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> Dict[str, str]:
        """Hash password with salt."""
        if salt is None:
            salt = bcrypt.gensalt()
        elif isinstance(salt, str):
            salt = salt.encode('utf-8')
        
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        return {
            "hash": hashed.decode('utf-8'),
            "salt": salt.decode('utf-8')
        }
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 1000) -> str:
        """Sanitize user input."""
        if not isinstance(input_str, str):
            input_str = str(input_str)
        
        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_str)
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        # Remove potential script tags
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        return sanitized.strip()
    
    @staticmethod
    def generate_csrf_token() -> str:
        """Generate CSRF token."""
        return SecurityUtils.generate_secure_token(32)

class DateTimeUtils:
    """Common date/time utilities."""
    
    @staticmethod
    def now_iso() -> str:
        """Get current datetime in ISO format."""
        return from datetime import datetime
datetime.now().isoformat()
    
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
        now = from datetime import datetime
datetime.now()
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
        now = from datetime import datetime
datetime.now()
        if dt.tzinfo is not None:
            now = now.replace(tzinfo=dt.tzinfo)
        
        return (now - dt).total_seconds() > ttl_seconds

class FileUtils:
    """Common file utilities."""
    
    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> Path:
        """Ensure directory exists."""
        path = from pathlib import Path
Path(path)
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
    def success_response(data: Any = None, message: str = "Success") -> Dict[str, Any]:
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
    def error_response(message: str, error_code: str = None, details: Any = None) -> Dict[str, Any]:
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
    def paginated_response(data: List[Any], page: int, per_page: int, 
                          total: int, message: str = "Success") -> Dict[str, Any]:
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
    def setup_logger(name: str, level: str = "INFO", 
                    format_string: str = None) -> logging.Logger:
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
    def log_performance(func_name: str, duration: float, 
                       logger: logging.Logger = None):
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
    async def retry_async(coro_func: Callable, max_retries: int = 3, 
                         delay: float = 1.0, backoff: float = 2.0):
        """Retry async function with exponential backoff."""
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                return await coro_func()
            except Exception as e:
                last_exception = e
                
                if attempt < max_retries:
                    wait_time = delay * (backoff ** attempt)
                    logger.warning(f"Attempt {attempt + 1} failed, retrying in {wait_time}s: {e}")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"All {max_retries + 1} attempts failed")
        
        raise last_exception
    
    @staticmethod
    async def gather_with_concurrency(tasks: List, max_concurrent: int = 10):
        """Gather tasks with concurrency limit."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def controlled_task(task):
            async with semaphore:
                return await task
        
        return await asyncio.gather(*[controlled_task(task) for task in tasks])

# Performance monitoring decorator
def monitor_performance(logger: logging.Logger = None):
    """Decorator to monitor function performance."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                LoggingUtils.log_performance(func.__name__, duration, logger)
                return result
            except Exception as e:
                duration = time.time() - start_time
                if logger:
                    logger.error(f"Function {func.__name__} failed after {duration:.3f}s: {e}")
                raise
        
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                LoggingUtils.log_performance(func.__name__, duration, logger)
                return result
            except Exception as e:
                duration = time.time() - start_time
                if logger:
                    logger.error(f"Function {func.__name__} failed after {duration:.3f}s: {e}")
                raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
    return decorator
