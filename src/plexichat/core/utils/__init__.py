"""PlexiChat Utilities"""

import logging
from typing import Any, Dict, List

try:
    from .helpers import (
        StringUtils, DateTimeUtils, HashUtils, JsonUtils, ListUtils,
        DictUtils, AsyncUtils, PerformanceUtils,
        generate_id, current_timestamp, format_bytes, safe_int, safe_float, safe_bool
    )
    logger = logging.getLogger(__name__)
    logger.info("Utility modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import utility modules: {e}")

__all__ = [
    "StringUtils",
    "DateTimeUtils",
    "HashUtils",
    "JsonUtils",
    "ListUtils",
    "DictUtils",
    "AsyncUtils",
    "PerformanceUtils",
    "generate_id",
    "current_timestamp",
    "format_bytes",
    "safe_int",
    "safe_float",
    "safe_bool",
]

__version__ = "1.0.0"
