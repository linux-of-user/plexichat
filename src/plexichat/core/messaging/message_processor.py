"""
PlexiChat Message Processor

Message processing with threading and performance optimization.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
import logging
import time
from typing import Any

try:
    from plexichat.core.database.manager import database_manager, execute_query
except ImportError:
    database_manager = None
    execute_query = None

try:
    from plexichat.core.threading.thread_manager import (
        async_thread_manager,
        submit_task,
    )
except ImportError:
    async_thread_manager = None
    submit_task = None

try:
    from plexichat.core.logging import (
        MetricType,  # type: ignore
        get_performance_logger,
    )
    from plexichat.core.performance.optimization_engine import (
        PerformanceOptimizationEngine,
    )
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None
    MetricType = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None


@dataclass
class MessageData:
    """Message data structure."""

    message_id: str
    sender_id: int
    recipient_id: int | None
    channel_id: int | None
    content: str
    message_type: str
    timestamp: datetime
    metadata: dict[str, Any]


class MessageProcessor:
    """Message processor with threading support."""

    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager
        self.message_queue = asyncio.Queue()
        self.processing = False
        self.processors = {
            "text": self._process_text_message,
            "image": self._process_image_message,
            "file": self._process_file_message,
            "system": self._process_system_message,
        }

    async def start_processing(self):
        """Start message processing loop."""
        if self.processing:
            return

        self.processing = True
        asyncio.create_task(self._processing_loop())
        logger.info("Message processor started")

    async def stop_processing(self):
        """Stop message processing."""
        self.processing = False
        logger.info("Message processor stopped")

    async def _processing_loop(self):
        """Main message processing loop."""
        while self.processing:
            try:
                # Get message from queue with timeout
                message = await asyncio.wait_for(self.message_queue.get(), timeout=1.0)

                # Process message in thread
                if self.async_thread_manager:
                    await self.async_thread_manager.run_in_thread(
                        self._process_message_sync, message
                    )
                else:
                    await self._process_message(message)

                self.message_queue.task_done()

            except TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Message processing error: {e}")

    def _process_message_sync(self, message: MessageData):
        """Synchronous message processing for threading."""
        try:
            processor = self.processors.get(
                message.message_type, self._process_default_message
            )
            result = processor(message)

            if self.performance_logger:
                self.performance_logger.increment_counter("messages_processed", 1)

            return result
        except Exception as e:
            logger.error(f"Error processing message {message.message_id}: {e}")
            if self.performance_logger:
                self.performance_logger.increment_counter(
                    "message_processing_errors", 1
                )
            raise

    async def _process_message(self, message: MessageData):
        """Async message processing."""
        try:
            start_time = time.time()

            # Process based on message type
            processor = self.processors.get(
                message.message_type, self._process_default_message
            )

            if asyncio.iscoroutinefunction(processor):
                result = await processor(message)
            else:
                result = processor(message)

            # Store processed message
            await self._store_processed_message(message, result)

            # Performance tracking
            if self.performance_logger:
                duration = time.time() - start_time
                self.performance_logger.record_timer(
                    "message_processing_duration", duration
                )
                self.performance_logger.increment_counter("messages_processed", 1)

            return result

        except Exception as e:
            logger.error(f"Error processing message {message.message_id}: {e}")
            if self.performance_logger:
                self.performance_logger.increment_counter(
                    "message_processing_errors", 1
                )
            raise

    def _process_text_message(self, message: MessageData) -> dict[str, Any]:
        """Process text message."""
        try:
            # Extract mentions
            mentions = self._extract_mentions(message.content)

            # Extract hashtags
            hashtags = self._extract_hashtags(message.content)

            # Extract URLs
            urls = self._extract_urls(message.content)

            # Content analysis
            word_count = len(message.content.split())
            char_count = len(message.content)

            return {
                "processed_content": message.content,
                "mentions": mentions,
                "hashtags": hashtags,
                "urls": urls,
                "word_count": word_count,
                "char_count": char_count,
                "sentiment": self._analyze_sentiment(message.content),
            }
        except Exception as e:
            logger.error(f"Error processing text message: {e}")
            return {"error": str(e)}

    def _process_image_message(self, message: MessageData) -> dict[str, Any]:
        """Process image message."""
        try:
            # Extract image metadata from message
            image_data = message.metadata.get("image", {})

            return {
                "image_url": image_data.get("url"),
                "image_size": image_data.get("size"),
                "image_type": image_data.get("type"),
                "alt_text": image_data.get("alt_text", ""),
                "processed": True,
            }
        except Exception as e:
            logger.error(f"Error processing image message: {e}")
            return {"error": str(e)}

    def _process_file_message(self, message: MessageData) -> dict[str, Any]:
        """Process file message."""
        try:
            # Extract file metadata
            file_data = message.metadata.get("file", {})

            return {
                "file_name": file_data.get("name"),
                "file_size": file_data.get("size"),
                "file_type": file_data.get("type"),
                "file_url": file_data.get("url"),
                "virus_scan_status": "pending",
                "processed": True,
            }
        except Exception as e:
            logger.error(f"Error processing file message: {e}")
            return {"error": str(e)}

    def _process_system_message(self, message: MessageData) -> dict[str, Any]:
        """Process system message."""
        try:
            return {
                "system_type": message.metadata.get("system_type", "unknown"),
                "processed": True,
                "timestamp": message.timestamp.isoformat(),
            }
        except Exception as e:
            logger.error(f"Error processing system message: {e}")
            return {"error": str(e)}

    def _process_default_message(self, message: MessageData) -> dict[str, Any]:
        """Default message processing."""
        return {
            "message_type": message.message_type,
            "processed": True,
            "content_length": len(message.content),
        }

    def _extract_mentions(self, content: str) -> list[str]:
        """Extract @mentions from content."""
        import re

        mentions = re.findall(r"@(\w+)", content)
        return list(set(mentions))

    def _extract_hashtags(self, content: str) -> list[str]:
        """Extract #hashtags from content."""
        import re

        hashtags = re.findall(r"#(\w+)", content)
        return list(set(hashtags))

    def _extract_urls(self, content: str) -> list[str]:
        """Extract URLs from content."""

        url_pattern = r"https?://[^\s<>]+"
