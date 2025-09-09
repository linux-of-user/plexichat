import asyncio
import logging
from typing import Any, Callable, List

# from plexichat.core.errors.base import PlexiError  # TODO: Import PlexiError when available


class PlexiError(Exception):
    pass  # Temporary definition for mypy


# from plexichat.core.utils.text_processing import extract_mentions, extract_hashtags  # TODO: implement text processing
from .base import MessageBaseProcessor

logger = logging.getLogger(__name__)


class MessageProcessor(MessageBaseProcessor):
    def __init__(self) -> None:
        super().__init__()
        self.name = "MessageProcessor"

    def _get_processor(self, msg_type: str) -> Callable[[dict], Any]:
        if msg_type == "text":
            return self._process_text_message
        else:
            raise PlexiError(f"Unsupported message type: {msg_type}")

    async def _process_text_message(self, message: dict) -> dict:
        """Type-specific processing for text messages including mentions and hashtags."""
        content = message.get("content", "")
        if not content:
            raise PlexiError("Text content required")

        # Extract mentions and hashtags
        mentions: List[str] = []  # TODO: extract_mentions(content)
        hashtags: List[str] = []  # TODO: extract_hashtags(content)

        processed = {
            "type": "text",
            "content": content,
            "mentions": mentions,
            "hashtags": hashtags,
            "timestamp": asyncio.get_event_loop().time(),
            "sender": message.get("sender", "unknown"),
        }

        logger.debug(f"Processed text message")  # TODO: with mentions and hashtags
        return processed

    async def start(self) -> None:
        """Start the processing loop."""
        logger.info(f"Starting {self.name}")
        await self._processing_loop()
