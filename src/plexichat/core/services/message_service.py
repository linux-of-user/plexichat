"""Shared message service used by both API and Web routers.
This module centralizes message validation, formatting, and persistence hooks
so features stay consistent across interfaces. No features are removed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
from typing import Any

from plexichat.infrastructure.utils.compilation import optimizer

from .message_checksum import calculate_checksum

logger = logging.getLogger(__name__)


@dataclass
class Message:
    content: str
    sender: str | None = None
    channel: str | None = None
    message_type: str = "text"
    flags: list[str] | None = None

    async def checksum(self) -> str:
        """Async wrapper for optimized checksum calculation."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, lambda: calculate_checksum(self.content)
        )


# Register the checksum function for compilation (Cython)
optimizer.register_function(
    "plexichat.core.services.message_service", "calculate_checksum", compiler="cython"
)


class MessageService:
    """Central service that implements the shared message logic.

    This is intentionally generic so both API and Web routers can delegate
    without losing any behavior. Extend with hooks for persistence, moderation,
    encryption, etc., preserving existing features.
    """

    def __init__(self) -> None:
        self._history_enabled = True

    def format_message(self, data: dict[str, Any]) -> dict[str, Any]:
        content = str(data.get("content", ""))
        sender = data.get("sender")
        channel = data.get("channel")
        message_type = data.get("type", "text")
        flags = data.get("flags", []) or []
        msg = Message(
            content=content,
            sender=sender,
            channel=channel,
            message_type=message_type,
            flags=flags,
        )
        result = {
            "content": msg.content,
            "sender": msg.sender,
            "channel": msg.channel,
            "type": msg.message_type,
            "flags": msg.flags,
            "checksum": msg.checksum(),
        }
        logger.debug("Formatted message: %s", result)
        return result

    async def save_if_enabled(self, formatted: dict[str, Any]) -> None:
        if not self._history_enabled:
            return
        # Hook for persistence; safe no-op default to avoid feature loss
        try:
            # e.g., await message_repository.save(formatted)
            logger.debug(
                "Persisting message (noop hook): %s", formatted.get("checksum")
            )
        except Exception as e:
            logger.warning("Message persistence hook failed: %s", e)

    def enable_history(self, enabled: bool) -> None:
        self._history_enabled = enabled


# Singleton-like shared instance
message_service = MessageService()
