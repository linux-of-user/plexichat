"""
PlexiChat Infrastructure Utilities
Consolidated infrastructure utilities for monitoring, security, and performance.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from functools import wraps

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """Simple performance monitoring."""

    def __init__(self):
        self.metrics: Dict[str, List[float]] = defaultdict(list)
        self.start_times: Dict[str, float] = {}

    def start_timer(self, name: str):
        """Start a performance timer."""
        self.start_times[name] = time.time()

    def end_timer(self, name: str) -> float:
        """End a performance timer and record the duration."""
        if name in self.start_times:
            duration = time.time() - self.start_times[name]
            self.metrics[name].append(duration)
            del self.start_times[name]
            return duration
        return 0.0
    
    @asynccontextmanager
    async def timer(self, name: str):
        """Context manager for timing operations."""
        start_time = time.time()
        try:
            yield
        finally:
            duration = time.time() - start_time
            self.metrics[name].append(duration)
    
    def get_stats(self, name: str) -> Dict[str, float]:
        """Get statistics for a metric."""
        if name not in self.metrics or not self.metrics[name]:
            return {"count": 0, "avg": 0.0, "min": 0.0, "max": 0.0}

        values = self.metrics[name]
        return {
            "count": len(values),
            "avg": sum(values) / len(values),
            "min": min(values),
            "max": max(values),
            "total": sum(values)
        }
    
    def clear_metrics(self, name: Optional[str] = None):
        """Clear metrics for a specific name or all metrics."""
        if name:
            self.metrics.pop(name, None)
        else:
            self.metrics.clear()


class RateLimiter:
    """Simple rate limiter implementation."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)

    def is_allowed(self, identifier: str) -> bool:
        """Check if a request is allowed for the given identifier."""
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old requests
        request_times = self.requests[identifier]
        while request_times and request_times[0] < window_start:
            request_times.popleft()
        
        # Check if under limit
        if len(request_times) < self.max_requests:
            request_times.append(now)
            return True
        
        return False
    
    def get_remaining(self, identifier: str) -> int:
        """Get remaining requests for identifier."""
        now = time.time()
        window_start = now - self.window_seconds

        request_times = self.requests[identifier]
        # Count requests in current window
        current_requests = sum(1 for t in request_times if t >= window_start)
        return max(0, self.max_requests - current_requests)


class SecurityUtils:
    """Security utility functions."""

    @staticmethod
    def sanitize_input(text: str, max_length: int = 1000) -> str:
        """Sanitize user input."""
        if not isinstance(text, str):
            text = str(text)

        # Remove control characters except newlines and tabs
        sanitized = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t')

        # Limit length
        return sanitized[:max_length]

    @staticmethod
    def is_safe_path(path: str, base_path: str = ".") -> bool:
        """Check if a path is safe (no directory traversal)."""
        import os
        try:
            # Resolve paths
            abs_base = os.path.abspath(base_path)
            abs_path = os.path.abspath(os.path.join(base_path, path))

            # Check if the resolved path is within the base path
            return abs_path.startswith(abs_base)
        except (ValueError, OSError):
            return False

    @staticmethod
    def validate_ip(ip_address: str) -> bool:
        """Validate IP address format."""
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_file_upload(filename: str, content: bytes, max_size: int = 10*1024*1024) -> Dict[str, Any]:
        """Validate file upload for security."""
        result = {"valid": True, "errors": [], "warnings": []}

        try:
            # Check file size
            if len(content) > max_size:
                result["valid"] = False
                result["errors"].append(f"File too large (max {max_size} bytes)")

            # Check filename for dangerous patterns
            dangerous_patterns = [
                r'\.\./',  # Directory traversal
                r'[<>:"/\\|?*]',  # Invalid characters
                r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$',  # Windows reserved names
            ]

            import re
            for pattern in dangerous_patterns:
                if re.search(pattern, filename, re.IGNORECASE):
                    result["valid"] = False
                    result["errors"].append("Filename contains dangerous patterns")
                    break

            # Check for executable file extensions
            dangerous_extensions = ['.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js']
            if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
                result["valid"] = False
                result["errors"].append("Executable files not allowed")

            # Basic malware signature check (simplified)
            malware_signatures = [b'MZ', b'PK\x03\x04', b'\x7fELF']
            for sig in malware_signatures:
                if content.startswith(sig) and filename.lower().endswith(('.txt', '.json', '.csv')):
                    result["warnings"].append("File content doesn't match extension")
                    break

            return result
        except Exception as e:
            logger.error(f"Error validating file upload: {e}")
            return {"valid": False, "errors": ["Validation error"], "warnings": []}

    @staticmethod
    def hash_sensitive_data(data: str, salt: Optional[str] = None) -> str:
        """Hash sensitive data with salt."""
        import hashlib
        import secrets

        if salt is None:
            salt = secrets.token_hex(16)

        combined = f"{salt}{data}"
        hashed = hashlib.sha256(combined.encode()).hexdigest()
        return f"{salt}:{hashed}"

    @staticmethod
    def verify_sensitive_data(data: str, hashed_data: str) -> bool:
        """Verify sensitive data against hash."""
        try:
            salt, hash_value = hashed_data.split(":", 1)
            return SecurityUtils.hash_sensitive_data(data, salt) == hashed_data
        except ValueError:
            return False


class AsyncUtils:
    """Async utility functions."""

    @staticmethod
    async def run_with_timeout(coro, timeout_seconds: float):
        """Run a coroutine with timeout."""
        try:
            return await asyncio.wait_for(coro, timeout=timeout_seconds)
        except asyncio.TimeoutError:
            logger.warning(f"Operation timed out after {timeout_seconds} seconds")
            raise

    @staticmethod
    async def gather_with_limit(coroutines: List, limit: int = 10):
        """Run coroutines with concurrency limit."""
        semaphore = asyncio.Semaphore(limit)
        
        async def limited_coro(coro):
            async with semaphore:
                return await coro
        
        return await asyncio.gather(*[limited_coro(coro) for coro in coroutines])
    
    @staticmethod
    def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
        """Retry decorator for async functions."""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                last_exception = None
                current_delay = delay
                
                for attempt in range(max_attempts):
                    try:
                        return await func(*args, **kwargs)
                    except Exception as e:
                        last_exception = e
                        if attempt < max_attempts - 1:
                            logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {current_delay}s...")
                            await asyncio.sleep(current_delay)
                            current_delay *= backoff
                        else:
                            logger.error(f"All {max_attempts} attempts failed")
                
                if last_exception:
                    raise last_exception
                else:
                    raise RuntimeError("All attempts failed but no exception was captured")
            return wrapper
        return decorator


class CacheManager:
    """Simple in-memory cache manager."""

    def __init__(self, default_ttl: int = 3600):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a cache value with TTL."""
        expires_at = time.time() + (ttl or self.default_ttl)
        self.cache[key] = {
            "value": value,
            "expires_at": expires_at
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a cache value."""
        if key not in self.cache:
            return default
        
        entry = self.cache[key]
        if time.time() > entry["expires_at"]:
            del self.cache[key]
            return default
        
        return entry["value"]
    
    def delete(self, key: str) -> bool:
        """Delete a cache entry."""
        return self.cache.pop(key, None) is not None
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self.cache.clear()
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count removed."""
        now = time.time()
        expired_keys = [
            key for key, entry in self.cache.items()
            if now > entry["expires_at"]
        ]
        
        for key in expired_keys:
            del self.cache[key]
        
        return len(expired_keys)


def performance_timer(name: str):
    """Decorator for timing function execution."""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                logger.debug(f"{name} took {duration:.3f}s")
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                logger.debug(f"{name} took {duration:.3f}s")
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


# Global instances
performance_monitor = PerformanceMonitor()
cache_manager = CacheManager()
security_utils = SecurityUtils()
async_utils = AsyncUtils()

__all__ = [
    "PerformanceMonitor", "RateLimiter", "SecurityUtils", "AsyncUtils", "CacheManager",
    "performance_monitor", "cache_manager", "security_utils", "async_utils",
    "performance_timer"
]
