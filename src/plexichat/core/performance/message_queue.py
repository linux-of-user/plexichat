"""
Message Queue System
====================

High-performance async message queue for PlexiChat.
"""

import asyncio
from typing import Any, Optional, Callable
from collections import deque
from datetime import datetime, timezone

from plexichat.core.logging import get_logger

logger = get_logger(__name__)

class MessageQueue:
    """
    Async message queue with pub/sub support.
    """
    def __init__(self, max_size: int = 10000):
        self._queue: deque = deque(maxlen=max_size)
        self._subscribers: dict[str, list[Callable]] = {}
        self._lock = asyncio.Lock()
        self._processing = False
        
    async def publish(self, topic: str, message: Any):
        """Publish a message to a topic."""
        async with self._lock:
            self._queue.append({
                "topic": topic,
                "message": message,
                "timestamp": datetime.now(timezone.utc)
            })
            
        await self._notify_subscribers(topic, message)
        
    async def subscribe(self, topic: str, callback: Callable):
        """Subscribe to a topic."""
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        self._subscribers[topic].append(callback)
        logger.debug(f"Subscribed to topic: {topic}")
        
    async def _notify_subscribers(self, topic: str, message: Any):
        """Notify all subscribers of a topic."""
        if topic in self._subscribers:
            for callback in self._subscribers[topic]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(message)
                    else:
                        callback(message)
                except Exception as e:
                    logger.error(f"Subscriber callback error: {e}")
                    
    def size(self) -> int:
        """Get queue size."""
        return len(self._queue)
        
    async def clear(self):
        """Clear the queue."""
        async with self._lock:
            self._queue.clear()
            
# Global instance
message_queue = MessageQueue()
