"""
PlexiChat Core Utilities - SINGLE SOURCE OF TRUTH

Consolidates ALL utility functionality from:
- core/utils/helpers.py - INTEGRATED
- infrastructure/utils/common_utils.py - INTEGRATED
- infrastructure/utils/helpers_optimized.py - INTEGRATED
- All other utility modules - INTEGRATED

Provides a single, unified interface for all utility operations.
"""

import warnings
import logging
from typing import Any, Dict, List, Optional

# Import unified utilities system (NEW SINGLE SOURCE OF TRUTH)
try:
    from .unified_utilities import ()
        # Main utility classes
        StringUtils,
        DateTimeUtils,
        HashUtils,
        JsonUtils,
        ListUtils,
        DictUtils,
        AsyncUtils,
        FileUtils,
        SecurityUtils,
        ValidationUtils,
        PerformanceUtils,
        ResponseUtils,

        # Global instances
        performance_utils,

        # Convenience functions
        generate_id,
        current_timestamp,
        format_bytes,
        safe_int,
        safe_float,
        safe_bool,

        # Backward compatibility aliases
        StringUtilities,
        DateTimeUtilities,
        HashUtilities,
        JsonUtilities,
        ListUtilities,
        DictUtilities,
        AsyncUtilities,
        FileUtilities,
        SecurityUtilities,
        ValidationUtilities,
        PerformanceUtilities,
        ResponseUtilities,
    )

    logger = logging.getLogger(__name__)
    logger.info("Unified utilities system imported successfully")

except ImportError as e:
    # Fallback definitions if unified utilities system fails to import
    import logging
    import time
    import uuid

    warnings.warn()
        f"Failed to import unified utilities system: {e}. Using fallback utilities.",
        ImportWarning,
        stacklevel=2
    )

    logger = logging.getLogger(__name__)

    class StringUtils:
        @staticmethod
        def is_empty(value: Optional[str]) -> bool:
            return not value or not value.strip()

        @staticmethod
        def truncate(text: str, max_length: int, suffix: str = "...") -> str:
            if len(text) <= max_length:
                return text
            return text[:max_length - len(suffix)] + suffix

        @staticmethod
        def sanitize(text: str, allow_html: bool = False) -> str:
            if not text:
                return ""
            return text.strip()

    class DateTimeUtils:
        @staticmethod
        def timestamp() -> int:
            return int(time.time())

        @staticmethod
        def now_iso() -> str:
            from datetime import datetime, timezone
            return datetime.now(timezone.utc).isoformat()

    class HashUtils:
        @staticmethod
        def sha256(data: str) -> str:
            import hashlib
            return hashlib.sha256(data.encode()).hexdigest()

    class JsonUtils:
        @staticmethod
        def safe_loads(json_str: str, default: Any = None) -> Any:
            import json
            try:
                return json.loads(json_str)
            except:
                return default

        @staticmethod
        def safe_dumps(data: Any, default: Any = None) -> str:
            import json
            try:
                return json.dumps(data, default=str)
            except:
                return json.dumps(default) if default else "{}"

    class ListUtils:
        @staticmethod
        def chunk(lst: List[Any], chunk_size: int) -> List[List[Any]]:
            return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

        @staticmethod
        def deduplicate(lst: List[Any], key=None) -> List[Any]:
            if key is None:
                return list(dict.fromkeys(lst))
            seen = set()
            result = []
            for item in lst:
                item_key = key(item)
                if item_key not in seen:
                    seen.add(item_key)
                    result.append(item)
            return result

    class DictUtils:
        @staticmethod
        def safe_get(data: Dict[str, Any], key: str, default: Any = None) -> Any:
            return data.get(key, default)

        @staticmethod
        def merge(*dicts: Dict[str, Any]) -> Dict[str, Any]:
            result = {}
            for d in dicts:
                if isinstance(d, dict):
                    result.update(d)
            return result

    class AsyncUtils:
        @staticmethod
        async def run_with_timeout(coro, timeout: float, default: Any = None) -> Any:
            import asyncio
            try:
                return await asyncio.wait_for(coro, timeout=timeout)
            except asyncio.TimeoutError:
                return default

    class FileUtils:
        @staticmethod
        def format_bytes(bytes_value: int) -> str:
            value = float(bytes_value)
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if value < 1024.0:
                    return f"{value:.1f} {unit}"
                value /= 1024.0
            return f"{value:.1f} PB"

    class SecurityUtils:
        @staticmethod
        def generate_secure_token(length: int = 32) -> str:
            import secrets
            return secrets.token_urlsafe(length)

    class ValidationUtils:
        @staticmethod
        def is_email(email: str) -> bool:
            import re
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return bool(re.match(pattern, email))

    class PerformanceUtils:
        def __init__(self):
            self.timers = {}

        def start_timer(self, name: str):
            self.timers[name] = time.time()

        def stop_timer(self, name: str) -> float:
            if name in self.timers:
                duration = time.time() - self.timers[name]
                del self.timers[name]
                return duration
            return 0.0

    class ResponseUtils:
        @staticmethod
        def success_response(data: Any = None, message: str = "Success") -> Dict[str, Any]:
            response = {"success": True, "message": message}
            if data is not None:
                response["data"] = data
            return response

        @staticmethod
        def error_response(message: str, error_code: Optional[str] = None) -> Dict[str, Any]:
            response = {"success": False, "message": message}
            if error_code:
                response["error_code"] = error_code
            return response

    # Global instances
    performance_utils = PerformanceUtils()

    # Convenience functions
    def generate_id() -> str:
        return str(uuid.uuid4())

    def current_timestamp() -> int:
        return DateTimeUtils.timestamp()

    def format_bytes(bytes_value: int) -> str:
        return FileUtils.format_bytes(bytes_value)

    def safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def safe_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    def safe_bool(value: Any, default: bool = False) -> bool:
        try:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.lower() in ('true', '1', 'yes', 'on')
            return bool(value)
        except (ValueError, TypeError):
            return default

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

# Export all the main classes and functions
__all__ = [
    # Unified utilities system (NEW SINGLE SOURCE OF TRUTH)
    "StringUtils",
    "DateTimeUtils",
    "HashUtils",
    "JsonUtils",
    "ListUtils",
    "DictUtils",
    "AsyncUtils",
    "FileUtils",
    "SecurityUtils",
    "ValidationUtils",
    "PerformanceUtils",
    "ResponseUtils",

    # Global instances
    "performance_utils",

    # Convenience functions
    "generate_id",
    "current_timestamp",
    "format_bytes",
    "safe_int",
    "safe_float",
    "safe_bool",

    # Backward compatibility aliases
    "StringUtilities",
    "DateTimeUtilities",
    "HashUtilities",
    "JsonUtilities",
    "ListUtilities",
    "DictUtilities",
    "AsyncUtilities",
    "FileUtilities",
    "SecurityUtilities",
    "ValidationUtilities",
    "PerformanceUtilities",
    "ResponseUtilities",
]

__version__ = "3.0.0"
