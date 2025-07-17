"""
PlexiChat Utility Helpers

Common utility functions with threading and performance optimization.
"""

import asyncio
import hashlib
import json
import logging
import random
import string
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable
from uuid import uuid4

try:
    from plexichat.core.threading.thread_manager import async_thread_manager
except ImportError:
    async_thread_manager = None

try:
    from plexichat.core.analytics.analytics_manager import track_event
except ImportError:
    track_event = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

class StringUtils:
    """String utility functions."""
    
    @staticmethod
    def generate_random_string(length: int = 10, include_digits: bool = True, 
                             include_uppercase: bool = True, include_lowercase: bool = True,
                             include_special: bool = False) -> str:
        """Generate random string."""
        try:
            chars = ""
            if include_lowercase:
                chars += string.ascii_lowercase
            if include_uppercase:
                chars += string.ascii_uppercase
            if include_digits:
                chars += string.digits
            if include_special:
                chars += "!@#$%^&*"
            
            if not chars:
                chars = string.ascii_letters
            
            return ''.join(random.choice(chars) for _ in range(length))
            
        except Exception as e:
            logger.error(f"Error generating random string: {e}")
            return str(uuid4())[:length]
    
    @staticmethod
    def slugify(text: str, max_length: int = 50) -> str:
        """Convert text to URL-friendly slug."""
        try:
            import re
            
            # Convert to lowercase
            text = text.lower()
            
            # Replace spaces and special characters with hyphens
            text = re.sub(r'[^a-z0-9]+', '-', text)
            
            # Remove leading/trailing hyphens
            text = text.strip('-')
            
            # Limit length
            if len(text) > max_length:
                text = text[:max_length].rstrip('-')
            
            return text or "slug"
            
        except Exception as e:
            logger.error(f"Error creating slug: {e}")
            return "slug"
    
    @staticmethod
    def truncate(text: str, max_length: int = 100, suffix: str = "...") -> str:
        """Truncate text to maximum length."""
        try:
            if len(text) <= max_length:
                return text
            
            return text[:max_length - len(suffix)] + suffix
            
        except Exception as e:
            logger.error(f"Error truncating text: {e}")
            return text
    
    @staticmethod
    def sanitize_html(text: str) -> str:
        """Sanitize HTML content."""
        try:
            # Basic HTML sanitization
            html_chars = {
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#x27;',
                '&': '&amp;'
            }
            
            for char, replacement in html_chars.items():
                text = text.replace(char, replacement)
            
            return text
            
        except Exception as e:
            logger.error(f"Error sanitizing HTML: {e}")
            return text
    
    @staticmethod
    def extract_mentions(text: str) -> List[str]:
        """Extract @mentions from text."""
        try:
            import re
            
            pattern = r'@([a-zA-Z0-9_]+)'
            mentions = re.findall(pattern, text)
            return list(set(mentions))  # Remove duplicates
            
        except Exception as e:
            logger.error(f"Error extracting mentions: {e}")
            return []
    
    @staticmethod
    def extract_hashtags(text: str) -> List[str]:
        """Extract #hashtags from text."""
        try:
            import re
            
            pattern = r'#([a-zA-Z0-9_]+)'
            hashtags = re.findall(pattern, text)
            return list(set(hashtags))  # Remove duplicates
            
        except Exception as e:
            logger.error(f"Error extracting hashtags: {e}")
            return []

class DateTimeUtils:
    """DateTime utility functions."""
    
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
        try:
            return dt.strftime(format_str)
        except Exception as e:
            logger.error(f"Error formatting datetime: {e}")
            return str(dt)
    
    @staticmethod
    def parse_datetime(dt_str: str, format_str: str = "%Y-%m-%d %H:%M:%S") -> Optional[datetime]:
        """Parse datetime from string."""
        try:
            return datetime.strptime(dt_str, format_str)
        except Exception as e:
            logger.error(f"Error parsing datetime: {e}")
            return None
    
    @staticmethod
    def time_ago(dt: datetime) -> str:
        """Get human-readable time ago string."""
        try:
            now = datetime.now()
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
                
        except Exception as e:
            logger.error(f"Error calculating time ago: {e}")
            return "Unknown"
    
    @staticmethod
    def add_time(dt: datetime, days: int = 0, hours: int = 0, minutes: int = 0, seconds: int = 0) -> datetime:
        """Add time to datetime."""
        try:
            delta = timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
            return dt + delta
        except Exception as e:
            logger.error(f"Error adding time: {e}")
            return dt

class HashUtils:
    """Hashing utility functions."""
    
    @staticmethod
    def md5_hash(data: Union[str, bytes]) -> str:
        """Generate MD5 hash."""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            return hashlib.md5(data).hexdigest()
            
        except Exception as e:
            logger.error(f"Error generating MD5 hash: {e}")
            return ""
    
    @staticmethod
    def sha256_hash(data: Union[str, bytes]) -> str:
        """Generate SHA256 hash."""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            return hashlib.sha256(data).hexdigest()
            
        except Exception as e:
            logger.error(f"Error generating SHA256 hash: {e}")
            return ""
    
    @staticmethod
    def generate_checksum(file_path: str) -> str:
        """Generate file checksum."""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
            
        except Exception as e:
            logger.error(f"Error generating file checksum: {e}")
            return ""

class JsonUtils:
    """JSON utility functions."""
    
    @staticmethod
    def safe_json_loads(json_str: str, default: Any = None) -> Any:
        """Safely load JSON string."""
        try:
            return json.loads(json_str)
        except Exception as e:
            logger.error(f"Error loading JSON: {e}")
            return default
    
    @staticmethod
    def safe_json_dumps(data: Any, default: Any = None, indent: Optional[int] = None) -> str:
        """Safely dump data to JSON string."""
        try:
            return json.dumps(data, indent=indent, default=str)
        except Exception as e:
            logger.error(f"Error dumping JSON: {e}")
            return json.dumps(default) if default is not None else "{}"
    
    @staticmethod
    def pretty_json(data: Any) -> str:
        """Format JSON with pretty printing."""
        return JsonUtils.safe_json_dumps(data, indent=2)
    
    @staticmethod
    def flatten_dict(data: Dict[str, Any], separator: str = ".") -> Dict[str, Any]:
        """Flatten nested dictionary."""
        try:
            def _flatten(obj: Any, parent_key: str = "") -> Dict[str, Any]:
                items = []
                
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        new_key = f"{parent_key}{separator}{key}" if parent_key else key
                        items.extend(_flatten(value, new_key).items())
                else:
                    return {parent_key: obj}
                
                return dict(items)
            
            return _flatten(data)
            
        except Exception as e:
            logger.error(f"Error flattening dictionary: {e}")
            return data

class ListUtils:
    """List utility functions."""
    
    @staticmethod
    def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
        """Split list into chunks."""
        try:
            return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
        except Exception as e:
            logger.error(f"Error chunking list: {e}")
            return [lst]
    
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
    def safe_get(lst: List[Any], index: int, default: Any = None) -> Any:
        """Safely get item from list by index."""
        try:
            return lst[index] if 0 <= index < len(lst) else default
        except Exception:
            return default

class DictUtils:
    """Dictionary utility functions."""
    
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
    def merge_dicts(*dicts: Dict[str, Any]) -> Dict[str, Any]:
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

class AsyncUtils:
    """Async utility functions."""
    
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
    async def gather_with_limit(coroutines: List, limit: int = 10) -> List[Any]:
        """Run coroutines with concurrency limit."""
        try:
            semaphore = asyncio.Semaphore(limit)
            
            async def limited_coro(coro):
                async with semaphore:
                    return await coro
            
            limited_coroutines = [limited_coro(coro) for coro in coroutines]
            return await asyncio.gather(*limited_coroutines, return_exceptions=True)
            
        except Exception as e:
            logger.error(f"Error in limited gather: {e}")
            return []
    
    @staticmethod
    async def retry_async(func: Callable, max_retries: int = 3, delay: float = 1.0, 
                         backoff: float = 2.0, exceptions: tuple = (Exception,)) -> Any:
        """Retry async function with exponential backoff."""
        for attempt in range(max_retries + 1):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func()
                else:
                    return func()
            except exceptions as e:
                if attempt == max_retries:
                    raise e
                
                wait_time = delay * (backoff ** attempt)
                logger.warning(f"Attempt {attempt + 1} failed, retrying in {wait_time}s: {e}")
                await asyncio.sleep(wait_time)

class PerformanceUtils:
    """Performance utility functions."""
    
    @staticmethod
    def measure_time(func: Callable) -> Callable:
        """Decorator to measure function execution time."""
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                if performance_logger:
                    performance_logger.record_metric(f"{func.__name__}_duration", duration, "seconds")
                
                logger.debug(f"{func.__name__} executed in {duration:.3f}s")
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"{func.__name__} failed after {duration:.3f}s: {e}")
                raise
        
        return wrapper
    
    @staticmethod
    def measure_async_time(func: Callable) -> Callable:
        """Decorator to measure async function execution time."""
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                
                if performance_logger:
                    performance_logger.record_metric(f"{func.__name__}_duration", duration, "seconds")
                
                logger.debug(f"{func.__name__} executed in {duration:.3f}s")
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"{func.__name__} failed after {duration:.3f}s: {e}")
                raise
        
        return wrapper

# Convenience functions
def generate_id() -> str:
    """Generate unique ID."""
    return str(uuid4())

def current_timestamp() -> int:
    """Get current timestamp."""
    return int(time.time())

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
    except Exception:
        return default
