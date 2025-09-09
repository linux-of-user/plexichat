"""
PlexiChat WebSocket Manager

WebSocket management with threading and performance optimization.
"""

import asyncio
import json
import logging
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

if TYPE_CHECKING:
    from fastapi import WebSocket, WebSocketDisconnect
else:
    try:
        from fastapi import WebSocket, WebSocketDisconnect
    except ImportError:
        WebSocket = Any
        WebSocketDisconnect = Exception


class DatabaseManager:
    async def execute_query(self, *args, **kwargs):
        pass


database_manager = DatabaseManager()


class PerformanceLogger:
    def log_performance(self, *args, **kwargs):
        pass

    def record_metric(self, *args, **kwargs):
        pass


performance_logger = PerformanceLogger()


class AsyncThreadManager:
    def submit_task(self, *args, **kwargs):
        pass

    async def run_in_thread(self, *args, **kwargs):
        pass


async_thread_manager = AsyncThreadManager()


class CacheManager:
    def get(self, *args, **kwargs):
        return None

    def set(self, *args, **kwargs):
        pass

    def delete(self, *args, **kwargs):
        pass


cache_manager = CacheManager()

logger = logging.getLogger(__name__)


def cache_get(*args, **kwargs):
    return None


def cache_set(*args, **kwargs):
    pass


def cache_delete(*args, **kwargs):
    pass


class CacheKeyBuilder:
    def build(self, *args, **kwargs):
        return "cache_key"


def get_performance_logger():
    return PerformanceLogger()


logger = logging.getLogger(__name__)
performance_logger = get_performance_logger()


@dataclass
class WebSocketConnection:
    """WebSocket connection data."""

    websocket: WebSocket
    user_id: Optional[int]
    connection_id: str
    connected_at: datetime
    last_ping: datetime
    channels: Set[str]
    metadata: Dict[str, Any]


class WebSocketManager:
    """WebSocket manager with threading support."""

    def __init__(self):
        self.connections: Dict[str, WebSocketConnection] = {}
        self.user_connections: Dict[int, Set[str]] = {}
        self.channel_connections: Dict[str, Set[str]] = {}
        self.db_manager = database_manager
        self.performance_logger: PerformanceLogger = performance_logger
        self.async_thread_manager = async_thread_manager
        self.cache_manager = cache_manager

        # Message queue for broadcasting
        self.message_queue = asyncio.Queue()
        self.broadcasting = False

        # Statistics
        self.total_connections = 0
        self.total_messages = 0
        self.total_disconnections = 0
        # Thread events
        self.thread_subscribers: Dict[str, Set[str]] = (
            {}
        )  # thread_id -> set of connection_ids
        # Typing indicators
        self.typing_states: Dict[str, Dict[str, datetime]] = (
            {}
        )  # channel_id -> {user_id: last_typing_time}
        self.typing_timeout = 3.0  # seconds

        # Start typing cleanup task (will be started during app startup)
        self._cleanup_task = None

    async def start_cleanup_task(self):
        """Start the typing cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_typing_states())
            logger.info("WebSocket typing cleanup task started")

    async def stop_cleanup_task(self):
        """Stop the typing cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("WebSocket typing cleanup task stopped")

    async def start_broadcasting(self):
        """Start message broadcasting loop."""
        if self.broadcasting:
            return

        self.broadcasting = True
        asyncio.create_task(self._broadcast_loop())
        logger.info("WebSocket broadcasting started")

    async def stop_broadcasting(self):
        """Stop message broadcasting."""
        self.broadcasting = False
        logger.info("WebSocket broadcasting stopped")

    async def _broadcast_loop(self):
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

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Broadcasting error: {e}")

    def _broadcast_message_sync(self, message: Dict[str, Any]):
        """Synchronous message broadcasting for threading."""
        try:
            asyncio.create_task(self._broadcast_message(message))
        except Exception as e:
            logger.error(f"Error in sync broadcast: {e}")

    async def _broadcast_message(self, message: Dict[str, Any]):
        """Broadcast message to connections."""
        try:
            start_time = time.time()

            target_type = message.get("target_type", "all")
            target_id = message.get("target_id")
            content = message.get("content", {})

            connections_to_send = []

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
        self, connection: WebSocketConnection, message: Dict[str, Any]
    ):
        """Send message to specific connection."""
        try:
            await connection.websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.error(f"Error sending to connection {connection.connection_id}: {e}")
            # Remove failed connection
            await self.disconnect(connection.connection_id)

    async def connect(
        self, websocket: WebSocket, connection_id: str, user_id: Optional[int] = None
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

    async def disconnect(self, connection_id: str):
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

    async def send_to_thread(self, thread_id: str, message: Dict[str, Any]):
        """Send message to all connections subscribed to a thread."""
        await self.message_queue.put(
            {"target_type": "thread", "target_id": thread_id, "content": message}
        )

    async def broadcast_thread_event(
        self, thread_id: str, event_type: str, event_data: Dict[str, Any]
    ):
        """Broadcast a thread event to all subscribers."""
        event_message = {
            "type": f"thread_{event_type}",
            "thread_id": thread_id,
            "data": event_data,
            "timestamp": datetime.now().isoformat(),
        }
        await self.send_to_thread(thread_id, event_message)

    async def send_to_user(self, user_id: int, message: Dict[str, Any]):
        """Send message to specific user."""
        await self.message_queue.put(
            {"target_type": "user", "target_id": user_id, "content": message}
        )

    async def send_to_channel(self, channel: str, message: Dict[str, Any]):
        """Send message to channel."""
        await self.message_queue.put(
            {"target_type": "channel", "target_id": channel, "content": message}
        )

    async def broadcast_to_all(self, message: Dict[str, Any]):
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
        self, event_type: str, connection_id: str, user_id: Optional[int]
    ):
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

    def get_stats(self) -> Dict[str, Any]:
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

    async def _cleanup_typing_states(self):
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

    def get_typing_users(self, channel_id: str) -> List[str]:
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


# Convenience functions
async def connect_websocket(
    websocket: WebSocket, connection_id: str, user_id: Optional[int] = None
) -> bool:
    """Connect WebSocket to global manager."""
    return await websocket_manager.connect(websocket, connection_id, user_id)


async def send_to_thread(thread_id: str, message: Dict[str, Any]):
    """Send message to thread via global manager."""
    await websocket_manager.send_to_thread(thread_id, message)


async def broadcast_thread_event(
    thread_id: str, event_type: str, event_data: Dict[str, Any]
):
    """Broadcast thread event via global manager."""
    await websocket_manager.broadcast_thread_event(thread_id, event_type, event_data)


async def join_thread(connection_id: str, thread_id: str) -> bool:
    """Join thread via global manager."""
    return await websocket_manager.join_thread(connection_id, thread_id)


async def leave_thread(connection_id: str, thread_id: str) -> bool:
    """Leave thread via global manager."""
    return await websocket_manager.leave_thread(connection_id, thread_id)


async def disconnect_websocket(connection_id: str):
    """Disconnect WebSocket from global manager."""
    await websocket_manager.disconnect(connection_id)


async def send_to_user(user_id: int, message: Dict[str, Any]):
    """Send message to user via global manager."""
    await websocket_manager.send_to_user(user_id, message)


async def send_to_channel(channel: str, message: Dict[str, Any]):
    """Send message to channel via global manager."""
    await websocket_manager.send_to_channel(channel, message)


async def broadcast_message(message: Dict[str, Any]):
    """Broadcast message via global manager."""
    await websocket_manager.broadcast_to_all(message)


async def start_typing(connection_id: str, channel_id: str) -> bool:
    """Start typing indicator via global manager."""
    return await websocket_manager.start_typing(connection_id, channel_id)


async def stop_typing(connection_id: str, channel_id: str) -> bool:
    """Stop typing indicator via global manager."""
    return await websocket_manager.stop_typing(connection_id, channel_id)


def get_typing_users(channel_id: str) -> List[str]:
    """Get typing users via global manager."""
    return websocket_manager.get_typing_users(channel_id)
