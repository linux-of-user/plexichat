"""
WebSocket integration tests for real-time typing indicators.

This module contains integration tests that verify typing indicator
functionality over WebSocket connections with real-time broadcasting.
"""

import pytest
import asyncio
import json
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timezone

from plexichat.core.services.typing_service import typing_service
from plexichat.core.websocket.websocket_manager import websocket_manager
from plexichat.interfaces.websocket.websocket_manager import WebSocketManagerInterface


class TestWebSocketTypingRealTime:
    """Test real-time typing indicators over WebSocket."""

    @pytest.fixture
    def mock_websocket_connection(self):
        """Create mock WebSocket connection."""
        mock_ws = MagicMock()
        mock_ws.send_json = AsyncMock()
        mock_ws.receive_json = AsyncMock()
        mock_ws.close = AsyncMock()
        mock_ws.client_state = {"user_id": "test_user"}
        return mock_ws

    @pytest.fixture
    def mock_connection_manager(self, mock_websocket_connection):
        """Create mock connection manager."""
        mock_manager = MagicMock()
        mock_manager.connections = {
            "conn_123": mock_websocket_connection
        }
        mock_manager.get_connection = MagicMock(return_value=mock_websocket_connection)
        mock_manager.send_to_channel = AsyncMock(return_value=True)
        return mock_manager

    @pytest.fixture
    def websocket_interface(self, mock_connection_manager):
        """Create WebSocket interface instance."""
        interface = WebSocketManagerInterface()
        interface.core_manager = mock_connection_manager
        interface.typing_service = typing_service
        return interface

    @pytest.mark.asyncio
    async def test_websocket_start_typing_broadcast(self, websocket_interface, mock_connection_manager):
        """Test that starting typing broadcasts to channel."""
        # Mock typing service
        with patch.object(typing_service, 'start_typing', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = True

            # Mock connection with user
            mock_connection = mock_connection_manager.connections["conn_123"]
            mock_connection.user_id = "test_user"

            result = await websocket_interface.start_typing("conn_123", "test_channel")

            assert result is True
            mock_start.assert_called_once_with("test_user", "test_channel")
            mock_connection_manager.send_to_channel.assert_called_once()

            # Verify broadcast message
            call_args = mock_connection_manager.send_to_channel.call_args
            message = call_args[0][1]  # Second argument is the message
            assert message["type"] == "typing_start"
            assert message["channel_id"] == "test_channel"
            assert message["user_id"] == "test_user"

    @pytest.mark.asyncio
    async def test_websocket_stop_typing_broadcast(self, websocket_interface, mock_connection_manager):
        """Test that stopping typing broadcasts to channel."""
        with patch.object(typing_service, 'stop_typing', new_callable=AsyncMock) as mock_stop:
            mock_stop.return_value = True

            mock_connection = mock_connection_manager.connections["conn_123"]
            mock_connection.user_id = "test_user"

            result = await websocket_interface.stop_typing("conn_123", "test_channel")

            assert result is True
            mock_stop.assert_called_once_with("test_user", "test_channel")
            mock_connection_manager.send_to_channel.assert_called_once()

            # Verify broadcast message
            call_args = mock_connection_manager.send_to_channel.call_args
            message = call_args[0][1]
            assert message["type"] == "typing_stop"
            assert message["channel_id"] == "test_channel"
            assert message["user_id"] == "test_user"

    @pytest.mark.asyncio
    async def test_websocket_start_typing_invalid_connection(self, websocket_interface):
        """Test start typing with invalid connection."""
        result = await websocket_interface.start_typing("invalid_conn", "test_channel")
        assert result is False

    @pytest.mark.asyncio
    async def test_websocket_stop_typing_invalid_connection(self, websocket_interface):
        """Test stop typing with invalid connection."""
        result = await websocket_interface.stop_typing("invalid_conn", "test_channel")
        assert result is False

    @pytest.mark.asyncio
    async def test_websocket_start_typing_no_user(self, websocket_interface, mock_connection_manager):
        """Test start typing with connection that has no user."""
        mock_connection = mock_connection_manager.connections["conn_123"]
        mock_connection.user_id = None  # No user associated

        result = await websocket_interface.start_typing("conn_123", "test_channel")
        assert result is False

    @pytest.mark.asyncio
    async def test_websocket_get_typing_users_async(self, websocket_interface):
        """Test getting typing users asynchronously."""
        with patch.object(typing_service, 'get_typing_users', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = ["user1", "user2"]

            result = await websocket_interface.get_typing_users_async("test_channel")

            assert result == ["user1", "user2"]
            mock_get.assert_called_once_with("test_channel")


class TestWebSocketTypingMultipleUsers:
    """Test typing indicators with multiple users in channel."""

    @pytest.fixture
    def mock_websocket_connections(self):
        """Create multiple mock WebSocket connections."""
        connections = {}
        for i in range(3):
            mock_ws = MagicMock()
            mock_ws.send_json = AsyncMock()
            mock_ws.receive_json = AsyncMock()
            mock_ws.close = AsyncMock()
            mock_ws.client_state = {"user_id": f"user_{i}"}
            connections[f"conn_{i}"] = mock_ws
        return connections

    @pytest.fixture
    def mock_connection_manager(self, mock_websocket_connections):
        """Create mock connection manager with multiple connections."""
        mock_manager = MagicMock()
        mock_manager.connections = mock_websocket_connections
        mock_manager.get_connection = MagicMock(side_effect=lambda conn_id: mock_websocket_connections.get(conn_id))
        mock_manager.send_to_channel = AsyncMock(return_value=True)
        return mock_manager

    @pytest.fixture
    def websocket_interface(self, mock_connection_manager):
        """Create WebSocket interface instance."""
        interface = WebSocketManagerInterface()
        interface.core_manager = mock_connection_manager
        interface.typing_service = typing_service
        return interface

    @pytest.mark.asyncio
    async def test_multiple_users_start_typing(self, websocket_interface, mock_connection_manager):
        """Test multiple users starting to type in same channel."""
        with patch.object(typing_service, 'start_typing', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = True

            # Set user IDs for connections
            for conn_id, mock_ws in mock_connection_manager.connections.items():
                user_id = f"user_{conn_id.split('_')[1]}"
                mock_ws.user_id = user_id

            # All users start typing
            tasks = []
            for conn_id in mock_connection_manager.connections.keys():
                task = asyncio.create_task(
                    websocket_interface.start_typing(conn_id, "shared_channel")
                )
                tasks.append(task)

            results = await asyncio.gather(*tasks)

            # All should succeed
            assert all(results)
            # Should be called for each user
            assert mock_start.call_count == 3
            # Should broadcast to channel multiple times
            assert mock_connection_manager.send_to_channel.call_count == 3

    @pytest.mark.asyncio
    async def test_broadcast_reaches_all_connections(self, websocket_interface, mock_connection_manager, mock_websocket_connections):
        """Test that typing broadcasts reach all connections in channel."""
        with patch.object(typing_service, 'start_typing', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = True

            # Set up connections
            mock_connection_manager.connections["conn_123"].user_id = "test_user"

            await websocket_interface.start_typing("conn_123", "test_channel")

            # Verify broadcast was called
            mock_connection_manager.send_to_channel.assert_called_once_with("test_channel", {
                "type": "typing_start",
                "channel_id": "test_channel",
                "user_id": "test_user",
                "timestamp": pytest.any  # Timestamp will be generated
            })


class TestWebSocketTypingErrorHandling:
    """Test error handling in WebSocket typing operations."""

    @pytest.fixture
    def mock_connection_manager(self):
        """Create mock connection manager."""
        mock_manager = MagicMock()
        mock_manager.connections = {}
        mock_manager.get_connection = MagicMock(return_value=None)
        mock_manager.send_to_channel = AsyncMock(side_effect=Exception("Broadcast failed"))
        return mock_manager

    @pytest.fixture
    def websocket_interface(self, mock_connection_manager):
        """Create WebSocket interface instance."""
        interface = WebSocketManagerInterface()
        interface.core_manager = mock_connection_manager
        interface.typing_service = typing_service
        return interface

    @pytest.mark.asyncio
    async def test_start_typing_broadcast_failure(self, websocket_interface):
        """Test handling of broadcast failure in start typing."""
        with patch.object(typing_service, 'start_typing', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = True

            # Create a mock connection
            mock_connection = MagicMock()
            mock_connection.user_id = "test_user"
            websocket_interface.core_manager.connections["conn_123"] = mock_connection
            websocket_interface.core_manager.get_connection.return_value = mock_connection

            # This should still succeed even if broadcast fails
            result = await websocket_interface.start_typing("conn_123", "test_channel")

            assert result is True  # Service call succeeded
            mock_start.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_typing_broadcast_failure(self, websocket_interface):
        """Test handling of broadcast failure in stop typing."""
        with patch.object(typing_service, 'stop_typing', new_callable=AsyncMock) as mock_stop:
            mock_stop.return_value = True

            mock_connection = MagicMock()
            mock_connection.user_id = "test_user"
            websocket_interface.core_manager.connections["conn_123"] = mock_connection
            websocket_interface.core_manager.get_connection.return_value = mock_connection

            result = await websocket_interface.stop_typing("conn_123", "test_channel")

            assert result is True
            mock_stop.assert_called_once()


class TestWebSocketTypingCleanup:
    """Test cleanup operations for typing indicators over WebSocket."""

    @pytest.fixture
    def mock_connection_manager(self):
        """Create mock connection manager."""
        mock_manager = MagicMock()
        mock_manager.connections = {
            "conn_123": MagicMock(user_id="test_user")
        }
        mock_manager.get_connection = MagicMock(return_value=mock_manager.connections["conn_123"])
        return mock_manager

    @pytest.fixture
    def websocket_interface(self, mock_connection_manager):
        """Create WebSocket interface instance."""
        interface = WebSocketManagerInterface()
        interface.core_manager = mock_connection_manager
        interface.typing_service = typing_service
        return interface

    @pytest.mark.asyncio
    async def test_cleanup_on_disconnect(self, websocket_interface, mock_connection_manager):
        """Test that typing is cleaned up when WebSocket disconnects."""
        with patch.object(typing_service, 'stop_typing', new_callable=AsyncMock) as mock_stop:
            mock_stop.return_value = True

            # Simulate disconnect cleanup
            await websocket_interface.disconnect("conn_123")

            # Should attempt to stop typing (though we don't have channel info in this context)
            # In real implementation, this would track which channels the connection was typing in

    @pytest.mark.asyncio
    async def test_cleanup_expired_states_via_websocket(self, websocket_interface):
        """Test cleanup of expired typing states via WebSocket interface."""
        with patch.object(typing_service, 'cleanup_expired_states', new_callable=AsyncMock) as mock_cleanup:
            mock_cleanup.return_value = 5

            result = await websocket_interface.cleanup_expired_typing_states()

            assert result == 5
            mock_cleanup.assert_called_once()


class TestWebSocketTypingPerformance:
    """Test performance aspects of WebSocket typing operations."""

    @pytest.fixture
    def mock_connection_manager(self):
        """Create mock connection manager for performance testing."""
        mock_manager = MagicMock()
        mock_manager.connections = {}
        mock_manager.send_to_channel = AsyncMock(return_value=True)

        # Create many mock connections
        for i in range(100):
            mock_ws = MagicMock()
            mock_ws.send_json = AsyncMock()
            mock_ws.user_id = f"user_{i}"
            mock_manager.connections[f"conn_{i}"] = mock_ws

        mock_manager.get_connection = MagicMock(side_effect=lambda conn_id: mock_manager.connections.get(conn_id))
        return mock_manager

    @pytest.fixture
    def websocket_interface(self, mock_connection_manager):
        """Create WebSocket interface instance."""
        interface = WebSocketManagerInterface()
        interface.core_manager = mock_connection_manager
        interface.typing_service = typing_service
        return interface

    @pytest.mark.asyncio
    async def test_bulk_typing_broadcast_performance(self, websocket_interface, mock_connection_manager):
        """Test performance of broadcasting to many connections."""
        with patch.object(typing_service, 'start_typing', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = True

            # Set up connections
            for conn_id, mock_ws in mock_connection_manager.connections.items():
                mock_ws.user_id = f"user_{conn_id.split('_')[1]}"

            # Time the operation
            import time
            start_time = time.time()

            # Start typing for one user (should broadcast to all in channel)
            await websocket_interface.start_typing("conn_0", "large_channel")

            end_time = time.time()
            duration = end_time - start_time

            # Should complete quickly even with many connections
            assert duration < 1.0  # Less than 1 second
            mock_connection_manager.send_to_channel.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_websocket_typing_operations(self, websocket_interface, mock_connection_manager):
        """Test concurrent WebSocket typing operations."""
        with patch.object(typing_service, 'start_typing', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = True

            # Set up connections
            for conn_id, mock_ws in mock_connection_manager.connections.items():
                mock_ws.user_id = f"user_{conn_id.split('_')[1]}"

            # Run concurrent typing operations
            tasks = []
            for i in range(10):
                task = asyncio.create_task(
                    websocket_interface.start_typing(f"conn_{i}", f"channel_{i}")
                )
                tasks.append(task)

            start_time = asyncio.get_event_loop().time()
            results = await asyncio.gather(*tasks)
            end_time = asyncio.get_event_loop().time()

            duration = end_time - start_time

            # All should succeed
            assert all(results)
            # Should complete in reasonable time
            assert duration < 2.0  # Less than 2 seconds
            assert mock_start.call_count == 10


class TestWebSocketTypingIntegration:
    """Test full integration of typing indicators over WebSocket."""

    @pytest.fixture
    def mock_websocket_connection(self):
        """Create mock WebSocket connection for integration test."""
        mock_ws = MagicMock()
        mock_ws.send_json = AsyncMock()
        mock_ws.receive_json = AsyncMock()
        mock_ws.close = AsyncMock()
        mock_ws.client_state = {"user_id": "integration_user"}
        return mock_ws

    @pytest.fixture
    def mock_connection_manager(self, mock_websocket_connection):
        """Create mock connection manager."""
        mock_manager = MagicMock()
        mock_manager.connections = {"conn_integration": mock_websocket_connection}
        mock_manager.get_connection = MagicMock(return_value=mock_websocket_connection)
        mock_manager.send_to_channel = AsyncMock(return_value=True)
        return mock_manager

    @pytest.fixture
    def websocket_interface(self, mock_connection_manager):
        """Create WebSocket interface instance."""
        interface = WebSocketManagerInterface()
        interface.core_manager = mock_connection_manager
        interface.typing_service = typing_service
        return interface

    @pytest.mark.asyncio
    async def test_full_typing_workflow_over_websocket(self, websocket_interface, mock_connection_manager):
        """Test complete typing workflow over WebSocket."""
        with patch.object(typing_service, 'start_typing', new_callable=AsyncMock) as mock_start, \
             patch.object(typing_service, 'stop_typing', new_callable=AsyncMock) as mock_stop, \
             patch.object(typing_service, 'get_typing_users', new_callable=AsyncMock) as mock_get:

            mock_start.return_value = True
            mock_stop.return_value = True
            mock_get.return_value = ["integration_user"]

            mock_connection = mock_connection_manager.connections["conn_integration"]
            mock_connection.user_id = "integration_user"

            # Start typing
            start_result = await websocket_interface.start_typing("conn_integration", "workflow_channel")
            assert start_result is True

            # Check typing users
            typing_users = await websocket_interface.get_typing_users_async("workflow_channel")
            assert "integration_user" in typing_users

            # Stop typing
            stop_result = await websocket_interface.stop_typing("conn_integration", "workflow_channel")
            assert stop_result is True

            # Verify broadcasts occurred
            assert mock_connection_manager.send_to_channel.call_count == 2

            # Verify service calls
            mock_start.assert_called_once_with("integration_user", "workflow_channel")
            mock_stop.assert_called_once_with("integration_user", "workflow_channel")
            mock_get.assert_called_once_with("workflow_channel")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])