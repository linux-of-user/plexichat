"""
PlexiChat WebSocket Manager

WebSocket management with threading and performance optimization.
"""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging
import time
from typing import Any, Protocol

try:
    from fastapi import WebSocket
    from fastapi.websockets import WebSocketDisconnect
except ImportError:
    # Fallback types for testing or environments without FastAPI
    from typing import Any

    WebSocket = Any
    WebSocketDisconnect = Exception


class DatabaseManager(Protocol):
    async def execute_query(self, query: str, params: dict[str, Any]) -> Any: ...


class PerformanceLogger(Protocol):
    def log_performance(
        self, operation: str, duration: float, metadata: dict[str, Any] | None = None
    ) -> None: ...

    def record_metric(self, name: str, value: int | float, unit: str) -> None: ...

    def increment_counter(self, name: str, value: int = 1) -> None: ...


class AsyncThreadManager(Protocol):
    def submit_task(
        self, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any: ...

    async def run_in_thread(
        self, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any: ...


class CacheManager(Protocol):
    def get(self, key: str) -> Any | None: ...

    def set(self, key: str, value: Any, ttl: int | None = None) -> None: ...

    def delete(self, key: str) -> None: ...


# Mock implementations for fallback
class _MockDatabaseManager:
    async def execute_query(self, query: str, params: dict[str, Any]) -> Any:
        pass


class _MockPerformanceLogger:
    def log_performance(
        self, operation: str, duration: float, metadata: dict[str, Any] | None = None
    ) -> None:
        pass

    def record_metric(self, name: str, value: int | float, unit: str) -> None:
        pass

    def increment_counter(self, name: str, value: int = 1) -> None:
        pass


class _MockAsyncThreadManager:
    def submit_task(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        pass

    async def run_in_thread(
        self, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        pass


class _MockCacheManager:
    def get(self, key: str) -> Any | None:
        return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        pass

    def delete(self, key: str) -> None:
        pass


# Global instances
database_manager: DatabaseManager = _MockDatabaseManager()
performance_logger: PerformanceLogger = _MockPerformanceLogger()
async_thread_manager: AsyncThreadManager = _MockAsyncThreadManager()
cache_manager: CacheManager = _MockCacheManager()

logger = logging.getLogger(__name__)


@dataclass
class WebSocketConnection:
    """WebSocket connection data."""

    websocket: WebSocket
    user_id: int | None
    connection_id: str
    connected_at: datetime
    last_ping: datetime
    channels: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)


MessageContent = dict[str, Any]
MessageCallback = Callable[[MessageContent], Awaitable[None]]
EventCallback = Callable[[str, str, dict[str, Any]], Awaitable[None]]


class WebSocketManager:
    """WebSocket manager with threading support."""

    def __init__(self) -> None:
        self.connections: dict[str, WebSocketConnection] = {}
        self.user_connections: dict[int, set[str]] = {}
        self.channel_connections: dict[str, set[str]] = {}
        self.db_manager: DatabaseManager = database_manager
        self.performance_logger: PerformanceLogger = performance_logger
        self.async_thread_manager: AsyncThreadManager = async_thread_manager
        self.cache_manager: CacheManager = cache_manager

        # Message queue for broadcasting
        self.message_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.broadcasting: bool = False

        # Statistics
        self.total_connections: int = 0
        self.total_messages: int = 0
        self.total_disconnections: int = 0

        # Thread events
        self.thread_subscribers: dict[str, set[str]] = (
            {}
        )  # thread_id -> set of connection_ids

        # Typing indicators
        self.typing_states: dict[str, dict[str, datetime]] = (
            {}
        )  # channel_id -> {user_id: last_typing_time}
        self.typing_timeout: float = 3.0  # seconds

        # Cleanup task
        self._cleanup_task: asyncio.Task[None] | None = None

    async def start_cleanup_task(self) -> None:
        """Start the typing cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_typing_states())
            logger.info("WebSocket typing cleanup task started")

    async def stop_cleanup_task(self) -> None:
        """Stop the typing cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("WebSocket typing cleanup task stopped")

    async def start_broadcasting(self) -> None:
        """Start message broadcasting loop."""
        if self.broadcasting:
            return

        self.broadcasting = True
        asyncio.create_task(self._broadcast_loop())
        logger.info("WebSocket broadcasting started")

    async def stop_broadcasting(self) -> None:
        """Stop message broadcasting."""
        self.broadcasting = False
        logger.info("WebSocket broadcasting stopped")

    async def _broadcast_loop(self) -> None:
        """Main broadcasting loop."""
        while self.broadcasting:
            try:
                # Get message from queue with timeout
                message = await asyncio.wait_for(self.message_queue.get(), timeout=1.0)

                # Broadcast message
                if self.async_thread_manager:
                    await self.async_thread_manager.run_in_thread(
                        self._broadcast_message_sync, message
                    )
                else:
                    await self._broadcast_message(message)

                self.message_queue.task_done()

            except TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Broadcasting error: {e}")

    def _broadcast_message_sync(self, message: dict[str, Any]) -> None:
        """Synchronous message broadcasting for threading."""
        try:
            asyncio.create_task(self._broadcast_message(message))
        except Exception as e:
            logger.error(f"Error in sync broadcast: {e}")

    async def _broadcast_message(self, message: dict[str, Any]) -> None:
        """Broadcast message to connections."""
        try:
            start_time = time.time()

            target_type = message.get("target_type", "all")
            target_id = message.get("target_id")
            content = message.get("content", {})

            connections_to_send: list[WebSocketConnection] = []

            if target_type == "user" and target_id:
                # Send to specific user
                user_connections = self.user_connections.get(target_id, set())
                connections_to_send = [
                    self.connections[conn_id]
                    for conn_id in user_connections
                    if conn_id in self.connections
                ]
            elif target_type == "thread" and target_id:
                # Send to thread subscribers
                thread_connections = self.thread_subscribers.get(target_id, set())
                connections_to_send = [
                    self.connections[conn_id]
                    for conn_id in thread_connections
                    if conn_id in self.connections
                ]
            elif target_type == "channel" and target_id:
                # Send to channel
                channel_connections = self.channel_connections.get(target_id, set())
                connections_to_send = [
                    self.connections[conn_id]
                    for conn_id in channel_connections
                    if conn_id in self.connections
                ]
            else:
                # Send to all connections
                connections_to_send = list(self.connections.values())

            # Send messages concurrently
            tasks = []
            for connection in connections_to_send:
                task = self._send_to_connection(connection, content)
                tasks.append(task)

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            # Performance tracking
            if self.performance_logger:
                duration = time.time() - start_time
                self.performance_logger.record_metric(
                    "websocket_broadcast_duration", duration, "seconds"
                )
                self.performance_logger.record_metric(
                    "websocket_messages_sent", len(connections_to_send), "count"
                )

            self.total_messages += len(connections_to_send)

        except Exception as e:
            logger.error(f"Error broadcasting message: {e}")

    async def _send_to_connection(
        self, connection: WebSocketConnection, message: dict[str, Any]
    ) -> None:
        """Send message to specific connection."""
        try:
            await connection.websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.error(f"Error sending to connection {connection.connection_id}: {e}")
            # Remove failed connection
            await self.disconnect(connection.connection_id)

    async def connect(
        self, websocket: WebSocket, connection_id: str, user_id: int | None = None
    ) -> bool:
        """Connect new WebSocket."""
        try:
            await websocket.accept()

            connection = WebSocketConnection(
                websocket=websocket,
                user_id=user_id,
                connection_id=connection_id,
                connected_at=datetime.now(),
                last_ping=datetime.now(),
                channels=set(),
                metadata={},
            )

            # Store connection
            self.connections[connection_id] = connection

            # Index by user
            if user_id:
                if user_id not in self.user_connections:
                    self.user_connections[user_id] = set()
                self.user_connections[user_id].add(connection_id)

            # Log connection
            await self._log_connection_event("connect", connection_id, user_id)

            # Performance tracking
            if self.performance_logger:
                self.performance_logger.increment_counter("websocket_connections", 1)

            self.total_connections += 1

            logger.info(f"WebSocket connected: {connection_id} (user: {user_id})")
            return True

        except Exception as e:
            logger.error(f"Error connecting WebSocket {connection_id}: {e}")
            return False

    async def disconnect(self, connection_id: str) -> None:
        """Disconnect WebSocket."""
        try:
            connection = self.connections.get(connection_id)
            if not connection:
                return

            # Remove from user connections
            if connection.user_id:
                user_connections = self.user_connections.get(connection.user_id, set())
                user_connections.discard(connection_id)
                if not user_connections:
                    del self.user_connections[connection.user_id]

            # Remove from thread subscribers
            for thread_id in list(self.thread_subscribers.keys()):
                thread_connections = self.thread_subscribers.get(thread_id, set())
                thread_connections.discard(connection_id)
                if not thread_connections:
                    del self.thread_subscribers[thread_id]

            # Remove from channel connections
            for channel in connection.channels:
                channel_connections = self.channel_connections.get(channel, set())
                channel_connections.discard(connection_id)
                if not channel_connections:
                    del self.channel_connections[channel]

            # Remove connection
            del self.connections[connection_id]

            # Log disconnection
            await self._log_connection_event(
                "disconnect", connection_id, connection.user_id
            )

            # Performance tracking
            if self.performance_logger:
                self.performance_logger.increment_counter("websocket_disconnections", 1)

            self.total_disconnections += 1

            logger.info(f"WebSocket disconnected: {connection_id}")

        except Exception as e:
            logger.error(f"Error disconnecting WebSocket {connection_id}: {e}")

    async def join_channel(self, connection_id: str, channel: str) -> bool:
        """Join connection to channel."""
        try:
            connection = self.connections.get(connection_id)
            if not connection:
                return False

            # Add to connection channels
            connection.channels.add(channel)

            # Add to channel connections
            if channel not in self.channel_connections:
                self.channel_connections[channel] = set()
            self.channel_connections[channel].add(connection_id)

            logger.info(f"Connection {connection_id} joined channel {channel}")
            return True

        except Exception as e:
            logger.error(f"Error joining channel {channel}: {e}")
            return False

    async def leave_channel(self, connection_id: str, channel: str) -> bool:
        """Leave connection from channel."""
        try:
            connection = self.connections.get(connection_id)
            if not connection:
                return False

            # Remove from connection channels
            connection.channels.discard(channel)

            # Remove from channel connections
            channel_connections = self.channel_connections.get(channel, set())
            channel_connections.discard(connection_id)
            if not channel_connections:
                del self.channel_connections[channel]

            logger.info(f"Connection {connection_id} left channel {channel}")
            return True

        except Exception as e:
            logger.error(f"Error leaving channel {channel}: {e}")
            return False

    async def join_thread(self, connection_id: str, thread_id: str) -> bool:
        """Join connection to thread for real-time updates."""
        try:
            connection = self.connections.get(connection_id)
            if not connection:
                return False

            # Add to thread subscribers
            if thread_id not in self.thread_subscribers:
                self.thread_subscribers[thread_id] = set()
            self.thread_subscribers[thread_id].add(connection_id)

            logger.info(f"Connection {connection_id} joined thread {thread_id}")
            return True

        except Exception as e:
            logger.error(f"Error joining thread {thread_id}: {e}")
            return False

    async def leave_thread(self, connection_id: str, thread_id: str) -> bool:
        """Leave connection from thread."""
        try:
            # Remove from thread subscribers
            if thread_id in self.thread_subscribers:
                self.thread_subscribers[thread_id].discard(connection_id)
                if not self.thread_subscribers[thread_id]:
                    del self.thread_subscribers[thread_id]

            logger.info(f"Connection {connection_id} left thread {thread_id}")
            return True

        except Exception as e:
            logger.error(f"Error leaving thread {thread_id}: {e}")
            return False

    async def send_to_thread(self, thread_id: str, message: dict[str, Any]) -> None:
        """Send message to all connections subscribed to a thread."""
        await self.message_queue.put(
            {"target_type": "thread", "target_id": thread_id, "content": message}
        )

    async def broadcast_thread_event(
        self, thread_id: str, event_type: str, event_data: dict[str, Any]
    ) -> None:
        """Broadcast a thread event to all subscribers."""
        event_message = {
            "type": f"thread_{event_type}",
            "thread_id": thread_id,
            "data": event_data,
            "timestamp": datetime.now().isoformat(),
        }
        await self.send_to_thread(thread_id, event_message)

    async def send_to_user(self, user_id: int, message: dict[str, Any]) -> None:
        """Send message to specific user."""
        await self.message_queue.put(
            {"target_type": "user", "target_id": user_id, "content": message}
        )

    async def send_to_channel(self, channel: str, message: dict[str, Any]) -> None:
        """Send message to channel."""
        await self.message_queue.put(
            {"target_type": "channel", "target_id": channel, "content": message}
        )

    async def broadcast_to_all(self, message: dict[str, Any]) -> None:
        """Broadcast message to all connections."""
        await self.message_queue.put({"target_type": "all", "content": message})

    async def ping_connection(self, connection_id: str) -> bool:
        """Ping connection to check if alive."""
        try:
            connection = self.connections.get(connection_id)
            if not connection:
                return False

            ping_message = {"type": "ping", "timestamp": datetime.now().isoformat()}

            await connection.websocket.send_text(json.dumps(ping_message))
            connection.last_ping = datetime.now()

            return True

        except Exception as e:
            logger.error(f"Error pinging connection {connection_id}: {e}")
            await self.disconnect(connection_id)
            return False

    async def _log_connection_event(
        self, event_type: str, connection_id: str, user_id: int | None
    ) -> None:
        """Log connection event to database."""
        try:
            if self.db_manager:
                query = """
                    INSERT INTO websocket_events (event_type, connection_id, user_id, timestamp)
                    VALUES (?, ?, ?, ?)
                """
                params = {
                    "event_type": event_type,
                    "connection_id": connection_id,
                    "user_id": user_id,
                    "timestamp": datetime.now(),
                }
                await self.db_manager.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error logging connection event: {e}")

    def get_connection_count(self) -> int:
        """Get current connection count."""
        return len(self.connections)

    def get_user_connection_count(self, user_id: int) -> int:
        """Get connection count for user."""
        return len(self.user_connections.get(user_id, set()))

    def get_channel_connection_count(self, channel: str) -> int:
        """Get connection count for channel."""
        return len(self.channel_connections.get(channel, set()))

    def get_stats(self) -> dict[str, Any]:
        """Get WebSocket statistics."""
        return {
            "active_connections": len(self.connections),
            "total_connections": self.total_connections,
            "total_messages": self.total_messages,
            "total_disconnections": self.total_disconnections,
            "active_users": len(self.user_connections),
            "active_channels": len(self.channel_connections),
            "queue_size": self.message_queue.qsize(),
            "broadcasting": self.broadcasting,
        }

    async def _cleanup_typing_states(self) -> None:
        """Periodically clean up expired typing states."""
        try:
            while True:
                await asyncio.sleep(1.0)  # Check every second
                current_time = datetime.now()

                for channel_id, users in list(self.typing_states.items()):
                    expired_users = []
                    for user_id, last_time in users.items():
                        if (
                            current_time - last_time
                        ).total_seconds() > self.typing_timeout:
                            expired_users.append(user_id)

                    # Remove expired users
                    for user_id in expired_users:
                        del users[user_id]

                    # If no users left in channel, remove channel
                    if not users:
                        del self.typing_states[channel_id]

        except asyncio.CancelledError:
            logger.info("Typing cleanup task cancelled")
            raise
        except Exception as e:
            logger.error(f"Error in typing cleanup: {e}")

    async def start_typing(self, connection_id: str, channel_id: str) -> bool:
        """Start typing indicator for user in channel."""
        try:
            connection = self.connections.get(connection_id)
            if not connection or not connection.user_id:
                return False

            user_id = str(connection.user_id)

            # Initialize channel if not exists
            if channel_id not in self.typing_states:
                self.typing_states[channel_id] = {}

            # Update typing time
            self.typing_states[channel_id][user_id] = datetime.now()

            # Broadcast typing start to channel
            typing_message = {
                "type": "typing_start",
                "channel_id": channel_id,
                "user_id": user_id,
                "timestamp": datetime.now().isoformat(),
            }

            await self.send_to_channel(channel_id, typing_message)
            return True

        except Exception as e:
            logger.error(f"Error starting typing for {connection_id}: {e}")
            return False

    async def stop_typing(self, connection_id: str, channel_id: str) -> bool:
        """Stop typing indicator for user in channel."""
        try:
            connection = self.connections.get(connection_id)
            if not connection or not connection.user_id:
                return False

            user_id = str(connection.user_id)

            # Remove from typing states
            if channel_id in self.typing_states:
                if user_id in self.typing_states[channel_id]:
                    del self.typing_states[channel_id][user_id]

                # Clean up empty channel
                if not self.typing_states[channel_id]:
                    del self.typing_states[channel_id]

            # Broadcast typing stop to channel
            typing_message = {
                "type": "typing_stop",
                "channel_id": channel_id,
                "user_id": user_id,
                "timestamp": datetime.now().isoformat(),
            }

            await self.send_to_channel(channel_id, typing_message)
            return True

        except Exception as e:
            logger.error(f"Error stopping typing for {connection_id}: {e}")
            return False

    def get_typing_users(self, channel_id: str) -> list[str]:
        """Get list of users currently typing in channel."""
        if channel_id not in self.typing_states:
            return []

        current_time = datetime.now()
        typing_users = []

        for user_id, last_time in self.typing_states[channel_id].items():
            if (current_time - last_time).total_seconds() <= self.typing_timeout:
                typing_users.append(user_id)

        return typing_users


# Global WebSocket manager
websocket_manager = WebSocketManager()


# Convenience functions with proper type annotations
async def connect_websocket(
    websocket: WebSocket, connection_id: str, user_id: int | None = None
) -> bool:
    """Connect WebSocket to global manager."""
    return await websocket_manager.connect(websocket, connection_id, user_id)


async def send_to_thread(thread_id: str, message: dict[str, Any]) -> None:
    """Send message to thread via global manager."""
    await websocket_manager.send_to_thread(thread_id, message)


async def broadcast_thread_event(
    thread_id: str, event_type: str, event_data: dict[str, Any]
) -> None:
    """Broadcast thread event via global manager."""
    await websocket_manager.broadcast_thread_event(thread_id, event_type, event_data)


async def join_thread(connection_id: str, thread_id: str) -> bool:
    """Join thread via global manager."""
    return await websocket_manager.join_thread(connection_id, thread_id)


async def leave_thread(connection_id: str, thread_id: str) -> bool:
    """Leave thread via global manager."""
    return await websocket_manager.leave_thread(connection_id, thread_id)


async def disconnect_websocket(connection_id: str) -> None:
    """Disconnect WebSocket from global manager."""
    await websocket_manager.disconnect(connection_id)


async def send_to_user(user_id: int, message: dict[str, Any]) -> None:
    """Send message to user via global manager."""
    await websocket_manager.send_to_user(user_id, message)


async def send_to_channel(channel: str, message: dict[str, Any]) -> None:
    """Send message to channel via global manager."""
    await websocket_manager.send_to_channel(channel, message)


async def broadcast_message(message: dict[str, Any]) -> None:
    """Broadcast message via global manager."""
    await websocket_manager.broadcast_to_all(message)


async def start_typing(connection_id: str, channel_id: str) -> bool:
    """Start typing indicator via global manager."""
    return await websocket_manager.start_typing(connection_id, channel_id)


async def stop_typing(connection_id: str, channel_id: str) -> bool:
    """Stop typing indicator via global manager."""
    return await websocket_manager.stop_typing(connection_id, channel_id)


def get_typing_users(channel_id: str) -> list[str]:
    """Get typing users via global manager."""
    return websocket_manager.get_typing_users(channel_id)
