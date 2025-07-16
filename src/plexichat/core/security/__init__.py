"""PlexiChat Security"""

import logging
from typing import Any, Dict, Optional, Tuple, List

try:
    from .security_manager import (
        SecurityManager, SecurityEvent,
        security_manager, hash_password, verify_password,
        generate_token, verify_token, check_rate_limit, sanitize_input
    )
    logger = logging.getLogger(__name__)
    logger.info("Security modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import security modules: {e}")

__all__ = [
    "SecurityManager",
    "SecurityEvent",
    "security_manager",
    "hash_password",
    "verify_password",
    "generate_token",
    "verify_token",
    "check_rate_limit",
    "sanitize_input",
]

__version__ = "1.0.0"
