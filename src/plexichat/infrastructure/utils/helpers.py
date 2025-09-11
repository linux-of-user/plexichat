# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
import secrets
import string
import math
import re
import hashlib
import time

# Use EXISTING performance optimization engine
try:
    from plexichat.core.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class HelperUtilities:
    """Enhanced helper utilities using EXISTING systems."""
    def __init__(self):
        self.performance_logger = performance_logger

    def generate_uuid(self) -> str:
        """Generate UUID string."""
        return str(uuid.uuid4())

    def generate_short_id(self, length: int = 8) -> str:
        """Generate short ID."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def format_datetime(self, dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Format datetime to string."""
        try:
            return dt.strftime(format_str)
        except Exception as e:
            logger.error(f"Datetime formatting error: {e}")
            return str(dt)

    def parse_datetime(self, dt_str: str, format_str: str = "%Y-%m-%d %H:%M:%S") -> Optional[datetime]:
        """Parse datetime from string."""
        try:
            return datetime.strptime(dt_str, format_str)
        except Exception as e:
            logger.error(f"Datetime parsing error: {e}")
            return None

    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format."""
        try:
            if size_bytes == 0:
                return "0 B"

            size_names = ["B", "KB", "MB", "GB", "TB"]
            i = int(math.floor(math.log(size_bytes, 1024)))
            p = math.pow(1024, i)
            s = round(size_bytes / p, 2)
            return f"{s} {size_names[i]}"
        except Exception as e:
            logger.error(f"File size formatting error: {e}")
            return f"{size_bytes} B"

    def truncate_text(self, text: str, max_length: int = 100, suffix: str = "...") -> str:
        """Truncate text to specified length."""
        try:
            if not text:
                return ""

            if len(text) <= max_length:
                return text

            return text[:max_length - len(suffix)] + suffix
        except Exception as e:
            logger.error(f"Text truncation error: {e}")
            return str(text)[:max_length] if text else ""

    def slugify(self, text: str) -> str:
        """Convert text to URL-friendly slug."""
        try:
            # Convert to lowercase
            text = text.lower()

            # Replace spaces and special characters with hyphens
            text = re.sub(r'[^\w\s-]', '', text)
            text = re.sub(r'[-\s]+', '-', text)

            # Remove leading/trailing hyphens
            text = text.strip('-')

            return text
        except Exception as e:
            logger.error(f"Slugify error: {e}")
            return str(text).lower().replace(' ', '-')

    def deep_merge_dicts(self, dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        try:
            result = dict1.copy()

            for key, value in dict2.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = self.deep_merge_dicts(result[key], value)
                else:
                    result[key] = value

            return result
        except Exception as e:
            logger.error(f"Dict merge error: {e}")
            return dict1

    def safe_json_loads(self, json_str: str, default: Any = None) -> Any:
        """Safely load JSON with default fallback."""
        try:
            return json.loads(json_str) if json_str else default
        except Exception as e:
            logger.error(f"JSON loads error: {e}")
            return default

    def safe_json_dumps(self, data: Any, default: str = "{}") -> str:
        """Safely dump JSON with default fallback."""
        try:
            return json.dumps(data, default=str, ensure_ascii=False)
        except Exception as e:
            logger.error(f"JSON dumps error: {e}")
            return default

    def extract_mentions(self, text: str) -> List[str]:
        """Extract @mentions from text."""
        try:
            mentions = re.findall(r'@(\w+)', text)
            return list(set(mentions))  # Remove duplicates
        except Exception as e:
            logger.error(f"Mention extraction error: {e}")
            return []

    def extract_hashtags(self, text: str) -> List[str]:
        """Extract #hashtags from text."""
        try:
            hashtags = re.findall(r'#(\w+)', text)
            return list(set(hashtags))  # Remove duplicates
        except Exception as e:
            logger.error(f"Hashtag extraction error: {e}")
            return []

    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text."""
        try:
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            urls = re.findall(url_pattern, text)
            return list(set(urls))  # Remove duplicates
        except Exception as e:
            logger.error(f"URL extraction error: {e}")
            return []

    def calculate_reading_time(self, text: str, words_per_minute: int = 200) -> int:
        """Calculate estimated reading time in minutes."""
        try:
            word_count = len(text.split())
            reading_time = max(1, round(word_count / words_per_minute))
            return reading_time
        except Exception as e:
            logger.error(f"Reading time calculation error: {e}")
            return 1

    def generate_color_from_string(self, text: str) -> str:
        """Generate consistent color hex code from string."""
        try:
            # Create hash of the string
            hash_object = hashlib.md5(text.encode())
            hex_dig = hash_object.hexdigest()

            # Take first 6 characters as color
            color = hex_dig[:6]

            return f"#{color}"
        except Exception as e:
            logger.error(f"Color generation error: {e}")
            return "#000000"

    def paginate_list(self, items: List[Any], page: int, per_page: int) -> Dict[str, Any]:
        """Paginate a list of items."""
        try:
            total_items = len(items)
            total_pages = (total_items + per_page - 1) // per_page

            start_index = (page - 1) * per_page
            end_index = start_index + per_page

            paginated_items = items[start_index:end_index]

            return {
                "items": paginated_items,
                "page": page,
                "per_page": per_page,
                "total_items": total_items,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1
            }
        except Exception as e:
            logger.error(f"Pagination error: {e}")
            return {
                "items": [],
                "page": 1,
                "per_page": per_page,
                "total_items": 0,
                "total_pages": 0,
                "has_next": False,
                "has_prev": False
            }

    def debounce(self, wait_time: float):
        """Debounce decorator for functions."""
        def decorator(func):
            last_called = [0.0]

            def wrapper(*args, **kwargs):
                now = time.time()

                if now - last_called[0] >= wait_time:
                    last_called[0] = now
                    return func(*args, **kwargs)

                return None

            return wrapper
        return decorator

    def retry_on_failure(self, max_retries: int = 3, delay: float = 1.0):
        """Retry decorator for functions."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                last_exception = None

                for attempt in range(max_retries + 1):
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        last_exception = e
                        if attempt < max_retries:
                            time.sleep(delay * (attempt + 1))
                        else:
                            logger.error(f"Function {func.__name__} failed after {max_retries} retries: {e}")

                if last_exception:
                    raise last_exception

            return wrapper
        return decorator

    async def async_retry_on_failure(self, max_retries: int = 3, delay: float = 1.0):
        """Async retry decorator for functions."""
        def decorator(func):
            async def wrapper(*args, **kwargs):
                last_exception = None

                for attempt in range(max_retries + 1):
                    try:
                        return await func(*args, **kwargs)
                    except Exception as e:
                        last_exception = e
                        if attempt < max_retries:
                            await asyncio.sleep(delay * (attempt + 1))
                        else:
                            logger.error(f"Async function {func.__name__} failed after {max_retries} retries: {e}")

                if last_exception:
                    raise last_exception

            return wrapper
        return decorator

# Global helper utilities
helper_utils = HelperUtilities()

# Convenience functions
def generate_uuid() -> str:
    """Generate UUID string."""
    return helper_utils.generate_uuid()

def generate_short_id(length: int = 8) -> str:
    """Generate short ID."""
    return helper_utils.generate_short_id(length)

def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format datetime to string."""
    return helper_utils.format_datetime(dt, format_str)

def parse_datetime(dt_str: str, format_str: str = "%Y-%m-%d %H:%M:%S") -> Optional[datetime]:
    """Parse datetime from string."""
    return helper_utils.parse_datetime(dt_str, format_str)

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format."""
    return helper_utils.format_file_size(size_bytes)

def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate text to specified length."""
    return helper_utils.truncate_text(text, max_length, suffix)

def slugify(text: str) -> str:
    """Convert text to URL-friendly slug."""
    return helper_utils.slugify(text)

def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely load JSON with default fallback."""
    return helper_utils.safe_json_loads(json_str, default)

def safe_json_dumps(data: Any, default: str = "{}") -> str:
    """Safely dump JSON with default fallback."""
    return helper_utils.safe_json_dumps(data, default)

def extract_mentions(text: str) -> List[str]:
    """Extract @mentions from text."""
    return helper_utils.extract_mentions(text)

def extract_hashtags(text: str) -> List[str]:
    """Extract #hashtags from text."""
    return helper_utils.extract_hashtags(text)

def extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    return helper_utils.extract_urls(text)

def paginate_list(items: List[Any], page: int, per_page: int) -> Dict[str, Any]:
    """Paginate a list of items."""
    return helper_utils.paginate_list(items, page, per_page)
