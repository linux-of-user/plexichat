import asyncio
import logging
import queue as std_queue
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

# from plexichat.core.database.storage import store_message  # TODO: implement storage
# from plexichat.core.errors.base import PlexiError  # TODO: Import PlexiError when available

class PlexiError(Exception):
    pass  # Temporary definition for mypy

# from plexichat.core.security.encryption import encrypt_message  # TODO: implement encryption

logger = logging.getLogger(__name__)


class MessageBaseProcessor(ABC):
    def __init__(self, queue: Optional[asyncio.Queue] = None):
        self.queue = queue or asyncio.Queue()
        self.metrics = {"processed": 0, "errors": 0}

    @abstractmethod
    def _get_processor(self, msg_type: str) -> Callable[[dict], Any]:
        """Subclasses must implement to return type-specific processor."""
        pass

    async def _process_message(self, message: dict) -> Any:
        """Generic message processing with validation, encryption, and storage."""
        try:
            # Validation
            if not message.get("type"):
                raise PlexiError("Message type required")

            # Get type-specific processor
            processor = self._get_processor(message["type"])

            # Type-specific processing
            processed = await processor(message)

            # Encryption (assuming outbound; decrypt for inbound if needed)
            if "content" in processed:
                # processed["content"] = encrypt_message(processed["content"])  # TODO: encrypt

            # Storage
            # TODO: Implement storage call

            self.metrics["processed"] += 1
            logger.info(f"Processed message of type {message['type']}")
            return processed

        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"Error processing message: {e}")
            raise

    async def _processing_loop(self) -> None:
        """Shared async processing loop for queue consumption."""
        while True:
            try:
                message = await self.queue.get()
                start_time = asyncio.get_event_loop().time()

                await self._process_message(message)

                end_time = asyncio.get_event_loop().time()
                logger.info(f"Message processed in {end_time - start_time:.2f}s")

                self.queue.task_done()

            except Exception as e:
                logger.error(f"Loop error: {e}")
                # Continue loop on error