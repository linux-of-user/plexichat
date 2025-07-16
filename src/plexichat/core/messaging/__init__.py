"""PlexiChat Messaging"""

import logging
from typing import Any, Dict, Optional

try:
    from .message_processor import (
        MessageProcessor, MessageData,
        message_processor, queue_message, process_message_now
    )
    logger = logging.getLogger(__name__)
    logger.info("Messaging modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import messaging modules: {e}")

__all__ = [
    "MessageProcessor",
    "MessageData",
    "message_processor",
    "queue_message",
    "process_message_now",
]

__version__ = "1.0.0"
