"""
Optimized WebSocket Service for Typing Indicators

High-performance WebSocket broadcasting optimized specifically for typing events.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Set

from plexichat.core.config import get_setting
from plexichat.core.websocket.websocket_manager import websocket_manager

logger = logging.getLogger(__name__)


@dataclass
class TypingBroadcastBatch:
    """Batch of typing events for efficient broadcasting."""

    channel_id: str
    events: List[Dict[str, Any]]
    timestamp: datetime
    priority: int = 1  # 1=normal, 2=high


class OptimizedWebSocketService:
    """Optimized WebSocket service for typing indicators."""

    def __init__(self):
        self.broadcast_queue: asyncio.Queue = asyncio.Queue()
        self.batch_queues: Dict[str, Deque[TypingBroadcastBatch]] = defaultdict(
            lambda: deque(maxlen=100)
        )
        self.channel_subscribers: Dict[str, Set[str]] = defaultdict(set)
        self.running = False
        self.batch_size = get_setting(
            "typing.broadcast_batch_size", 10
        )  # Max events per batch
        self.batch_timeout = get_setting(
            "typing.broadcast_interval_seconds", 0.1
        )  # Max wait time for batching
        self.max_concurrent_broadcasts = get_setting(
            "typing.max_concurrent_typing_users", 50
        )  # Max concurrent broadcast tasks

        # Performance metrics
        self.metrics = {
            "total_broadcasts": 0,
            "batched_broadcasts": 0,
            "individual_broadcasts": 0,
            "failed_broadcasts": 0,
            "avg_broadcast_time": 0.0,
            "total_connections_served": 0,
        }

    async def start(self) -> None:
        """Start the optimized broadcasting service."""
        if self.running:
            return

        self.running = True
        asyncio.create_task(self._batch_processor())
        asyncio.create_task(self._broadcast_worker())
        logger.info("Optimized WebSocket service started")

    async def stop(self) -> None:
        """Stop the optimized broadcasting service."""
        if not self.running:
            return

        self.running = False
        logger.info("Optimized WebSocket service stopped")

    async def broadcast_typing_event(
        self, channel_id: str, event: Dict[str, Any], priority: int = 1
    ) -> None:
        """Broadcast typing event with optimization."""
        if not self.running:
            # Fallback to direct broadcast
            await websocket_manager.send_to_channel(channel_id, event)
            return

        batch = TypingBroadcastBatch(
            channel_id=channel_id,
            events=[event],
            timestamp=datetime.now(timezone.utc),
            priority=priority,
        )

        # Add to batch queue for processing
        await self.broadcast_queue.put(batch)

        # Update metrics
        self.metrics["total_broadcasts"] += 1

    async def broadcast_typing_batch(
        self, channel_id: str, events: List[Dict[str, Any]], priority: int = 1
    ) -> None:
        """Broadcast multiple typing events as a batch."""
        if not events:
            return

        if not self.running or len(events) == 1:
            # Fallback to individual broadcasts
            for event in events:
                await websocket_manager.send_to_channel(channel_id, event)
            return

        batch = TypingBroadcastBatch(
            channel_id=channel_id,
            events=events,
            timestamp=datetime.now(timezone.utc),
            priority=priority,
        )

        await self.broadcast_queue.put(batch)
        self.metrics["total_broadcasts"] += len(events)

    async def _batch_processor(self) -> None:
        """Process and batch typing events."""
        batch_cache: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        while self.running:
            try:
                # Wait for first event or timeout
                try:
                    batch = await asyncio.wait_for(
                        self.broadcast_queue.get(), timeout=self.batch_timeout
                    )
                except asyncio.TimeoutError:
                    continue

                # Start batching with this event
                channel_id = batch.channel_id
                batch_cache[channel_id].extend(batch.events)

                # Try to collect more events for this channel within timeout
                end_time = time.time() + self.batch_timeout

                while (
                    time.time() < end_time
                    and len(batch_cache[channel_id]) < self.batch_size
                ):
                    try:
                        next_batch = await asyncio.wait_for(
                            self.broadcast_queue.get(),
                            timeout=max(0.001, end_time - time.time()),
                        )

                        if next_batch.channel_id == channel_id:
                            batch_cache[channel_id].extend(next_batch.events)
                            self.broadcast_queue.task_done()
                        else:
                            # Different channel, put back in queue
                            await self.broadcast_queue.put(next_batch)
                            break

                    except asyncio.TimeoutError:
                        break

                # Process the batch
                if batch_cache[channel_id]:
                    await self._process_batch(channel_id, batch_cache[channel_id])
                    batch_cache[channel_id].clear()

                self.broadcast_queue.task_done()

            except Exception as e:
                logger.error(f"Error in batch processor: {e}")
                await asyncio.sleep(0.1)

    async def _process_batch(
        self, channel_id: str, events: List[Dict[str, Any]]
    ) -> None:
        """Process a batch of typing events."""
        if len(events) == 1:
            # Single event, send directly
            await websocket_manager.send_to_channel(channel_id, events[0])
            self.metrics["individual_broadcasts"] += 1
        else:
            # Multiple events, create optimized batch message
            batch_message = {
                "type": "typing_batch",
                "channel_id": channel_id,
                "events": events,
                "count": len(events),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            await websocket_manager.send_to_channel(channel_id, batch_message)
            self.metrics["batched_broadcasts"] += 1

    async def _broadcast_worker(self) -> None:
        """Worker for handling broadcast tasks with concurrency control."""
        semaphore = asyncio.Semaphore(self.max_concurrent_broadcasts)

        while self.running:
            try:
                # Get batch from queue
                batch = await self.broadcast_queue.get()

                # Use semaphore to limit concurrent broadcasts
                async with semaphore:
                    start_time = time.time()

                    try:
                        if len(batch.events) == 1:
                            await websocket_manager.send_to_channel(
                                batch.channel_id, batch.events[0]
                            )
                            self.metrics["individual_broadcasts"] += 1
                        else:
                            # Send as batch
                            batch_message = {
                                "type": "typing_batch",
                                "channel_id": batch.channel_id,
                                "events": batch.events,
                                "count": len(batch.events),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                            await websocket_manager.send_to_channel(
                                batch.channel_id, batch_message
                            )
                            self.metrics["batched_broadcasts"] += 1

                        # Update performance metrics
                        broadcast_time = time.time() - start_time
                        self.metrics["avg_broadcast_time"] = (
                            (
                                self.metrics["avg_broadcast_time"]
                                * (self.metrics["total_broadcasts"] - len(batch.events))
                            )
                            + (broadcast_time * len(batch.events))
                        ) / self.metrics["total_broadcasts"]

                    except Exception as e:
                        logger.error(
                            f"Failed to broadcast typing batch to {batch.channel_id}: {e}"
                        )
                        self.metrics["failed_broadcasts"] += len(batch.events)

                self.broadcast_queue.task_done()

            except Exception as e:
                logger.error(f"Error in broadcast worker: {e}")
                await asyncio.sleep(0.1)

    async def get_channel_connection_count(self, channel_id: str) -> int:
        """Get number of connections in a channel."""
        return websocket_manager.get_channel_connection_count(channel_id)

    async def update_channel_subscribers(
        self, channel_id: str, connection_ids: Set[str]
    ) -> None:
        """Update subscriber list for a channel."""
        self.channel_subscribers[channel_id] = connection_ids.copy()

    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        return self.metrics.copy()

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check."""
        return {
            "service": "optimized_websocket",
            "running": self.running,
            "queue_size": self.broadcast_queue.qsize(),
            "metrics": self.get_metrics(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# Global optimized WebSocket service
optimized_websocket_service = OptimizedWebSocketService()


async def start_optimized_websocket_service() -> None:
    """Start the optimized WebSocket service."""
    await optimized_websocket_service.start()


async def stop_optimized_websocket_service() -> None:
    """Stop the optimized WebSocket service."""
    await optimized_websocket_service.stop()


async def broadcast_typing_event(
    channel_id: str, event: Dict[str, Any], priority: int = 1
) -> None:
    """Broadcast typing event via optimized service."""
    await optimized_websocket_service.broadcast_typing_event(
        channel_id, event, priority
    )


async def broadcast_typing_batch(
    channel_id: str, events: List[Dict[str, Any]], priority: int = 1
) -> None:
    """Broadcast typing events batch via optimized service."""
    await optimized_websocket_service.broadcast_typing_batch(
        channel_id, events, priority
    )


async def get_websocket_metrics() -> Dict[str, Any]:
    """Get WebSocket service metrics."""
    return optimized_websocket_service.get_metrics()


async def websocket_health_check() -> Dict[str, Any]:
    """Perform WebSocket service health check."""
    return await optimized_websocket_service.health_check()
