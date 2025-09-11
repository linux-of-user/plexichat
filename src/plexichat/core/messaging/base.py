from abc import ABC, abstractmethod
import asyncio
from collections.abc import Callable
import logging
from typing import Any

from plexichat.core.errors.base import PlexiError

logger = logging.getLogger(__name__)


class MessageBaseProcessor(ABC):
    """
    Base class for message processors that consume messages from an asyncio.Queue
    and process them with type-specific handlers.

    Subclasses must implement _get_processor to return a coroutine function for
    the given message type.
    """

    def __init__(self, queue: asyncio.Queue | None = None):
        self.queue = queue or asyncio.Queue()
        self.metrics = {"processed": 0, "errors": 0}

    @abstractmethod
    def _get_processor(self, msg_type: str) -> Callable[[dict], Any]:
        """Return a coroutine function that will process a message of the given type."""
        raise NotImplementedError

    async def _process_message(self, message: dict) -> Any:
        """Generic message processing with validation and type-specific handling."""
        try:
            # Validation
            if not message.get("type"):
                raise PlexiError("Message type required")

            # Get type-specific processor
            processor = self._get_processor(message["type"])

            # Type-specific processing
            processed = await processor(message)

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
