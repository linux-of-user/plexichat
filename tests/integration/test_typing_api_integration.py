"""
API integration tests for typing indicators REST endpoints.

This module contains integration tests that verify typing indicator
API endpoints work correctly with proper authentication and responses.
"""

import pytest
import asyncio
import json
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock

from plexichat.core.services.typing_service import typing_service


class TestTypingAPIEndpoints:
    """Test typing indicator REST API endpoints."""

    @pytest.fixture
    def mock_auth_dependency(self):
        """Mock authentication dependency."""
        async def mock_get_current_user():
            return {"id": "test_user", "username": "testuser"}
        return mock_get_current_user

    @pytest.fixture
    async def client(self, mock_auth_dependency):
        """Create test client with mocked auth."""
        from plexichat.interfaces.api.v1.typing import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        # Mock the get_current_user dependency
        with patch("plexichat.interfaces.api.v1.typing.get_current_user", mock_auth_dependency):
            async with AsyncClient(app=app, base_url="http://testserver") as client:
                yield client

    @pytest.mark.asyncio
    async def test_start_typing_endpoint_success(self, client, mock_auth_dependency):
        """Test successful typing start via API."""
        # Mock typing service
        with patch.object(typing_service, 'start_typing', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = True

            response = await client.post("/typing/start", json={
                "channel_id": "test_channel"
            })

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["action"] == "typing_started"
            assert data["user_id"] == "test_user"
            assert data["channel_id"] == "test_channel"

            mock_start.assert_called_once_with("test_user", "test_channel")

    @pytest.mark.asyncio
    async def test_start_typing_endpoint_failure(self, client):
        """Test typing start failure via API."""
        # Mock typing service to return False
        with patch.object(typing_service, 'start_typing', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = False

            response = await client.post("/typing/start", json={
                "channel_id": "test_channel"
            })

            assert response.status_code == 400
            data = response.json()
            assert "Failed to start typing" in data["detail"]

    @pytest.mark.asyncio
    async def test_stop_typing_endpoint_success(self, client):
        """Test successful typing stop via API."""
        # Mock typing service
        with patch.object(typing_service, 'stop_typing', new_callable=AsyncMock) as mock_stop:
            mock_stop.return_value = True

            response = await client.post("/typing/stop", json={
                "channel_id": "test_channel"
            })

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["action"] == "typing_stopped"
            assert data["user_id"] == "test_user"
            assert data["channel_id"] == "test_channel"

            mock_stop.assert_called_once_with("test_user", "test_channel")

    @pytest.mark.asyncio
    async def test_stop_typing_endpoint_failure(self, client):
        """Test typing stop failure via API."""
        with patch.object(typing_service, 'stop_typing', new_callable=AsyncMock) as mock_stop:
            mock_stop.return_value = False

            response = await client.post("/typing/stop", json={
                "channel_id": "test_channel"
            })

            assert response.status_code == 400
            data = response.json()
            assert "Failed to stop typing" in data["detail"]

    @pytest.mark.asyncio
    async def test_get_typing_status_endpoint(self, client):
        """Test getting typing status via API."""
        # Mock typing service
        with patch.object(typing_service, 'get_typing_users', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = ["user1", "user2", "user3"]

            response = await client.get("/typing/status/test_channel")

            assert response.status_code == 200
            data = response.json()
            assert data["channel_id"] == "test_channel"
            assert data["typing_users"] == ["user1", "user2", "user3"]
            assert data["count"] == 3

            mock_get.assert_called_once_with("test_channel")

    @pytest.mark.asyncio
    async def test_get_typing_status_empty_channel(self, client):
        """Test getting typing status for empty channel."""
        with patch.object(typing_service, 'get_typing_users', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = []

            response = await client.get("/typing/status/empty_channel")

            assert response.status_code == 200
            data = response.json()
            assert data["channel_id"] == "empty_channel"
            assert data["typing_users"] == []
            assert data["count"] == 0

    @pytest.mark.asyncio
    async def test_cleanup_expired_states_endpoint(self, client):
        """Test cleanup expired states via API."""
        with patch.object(typing_service, 'cleanup_expired_states', new_callable=AsyncMock) as mock_cleanup:
            mock_cleanup.return_value = 5

            response = await client.post("/typing/cleanup")

            assert response.status_code == 200
            data = response.json()
            assert "Cleaned up 5 expired typing states" in data["message"]

            mock_cleanup.assert_called_once()


class TestTypingAPIErrorHandling:
    """Test error handling in typing API endpoints."""

    @pytest.fixture
    async def client(self):
        """Create test client."""
        from plexichat.interfaces.api.v1.typing import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        async with AsyncClient(app=app, base_url="http://testserver") as client:
            yield client

    @pytest.mark.asyncio
    async def test_start_typing_service_exception(self, client):
        """Test handling of service exceptions in start typing."""
        with patch.object(typing_service, 'start_typing', side_effect=Exception("Service error")):
            response = await client.post("/typing/start", json={
                "channel_id": "test_channel"
            })

            assert response.status_code == 500
            data = response.json()
            assert "Failed to start typing" in data["detail"]

    @pytest.mark.asyncio
    async def test_stop_typing_service_exception(self, client):
        """Test handling of service exceptions in stop typing."""
        with patch.object(typing_service, 'stop_typing', side_effect=Exception("Service error")):
            response = await client.post("/typing/stop", json={
                "channel_id": "test_channel"
            })

            assert response.status_code == 500
            data = response.json()
            assert "Failed to stop typing" in data["detail"]

    @pytest.mark.asyncio
    async def test_get_typing_status_service_exception(self, client):
        """Test handling of service exceptions in get typing status."""
        with patch.object(typing_service, 'get_typing_users', side_effect=Exception("Service error")):
            response = await client.get("/typing/status/test_channel")

            assert response.status_code == 500
            data = response.json()
            assert "Failed to get typing users" in data["detail"]

    @pytest.mark.asyncio
    async def test_cleanup_service_exception(self, client):
        """Test handling of service exceptions in cleanup."""
        with patch.object(typing_service, 'cleanup_expired_states', side_effect=Exception("Service error")):
            response = await client.post("/typing/cleanup")

            assert response.status_code == 500
            data = response.json()
            assert "Failed to cleanup" in data["detail"]


class TestTypingAPIRequestValidation:
    """Test request validation for typing API endpoints."""

    @pytest.fixture
    async def client(self):
        """Create test client."""
        from plexichat.interfaces.api.v1.typing import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        async with AsyncClient(app=app, base_url="http://testserver") as client:
            yield client

    @pytest.mark.asyncio
    async def test_start_typing_missing_channel_id(self, client):
        """Test start typing with missing channel_id."""
        response = await client.post("/typing/start", json={})

        # This should fail validation
        assert response.status_code in [400, 422]

    @pytest.mark.asyncio
    async def test_stop_typing_missing_channel_id(self, client):
        """Test stop typing with missing channel_id."""
        response = await client.post("/typing/stop", json={})

        # This should fail validation
        assert response.status_code in [400, 422]

    @pytest.mark.asyncio
    async def test_start_typing_empty_channel_id(self, client):
        """Test start typing with empty channel_id."""
        response = await client.post("/typing/start", json={
            "channel_id": ""
        })

        # This should fail validation or service logic
        assert response.status_code in [400, 422, 500]

    @pytest.mark.asyncio
    async def test_stop_typing_empty_channel_id(self, client):
        """Test stop typing with empty channel_id."""
        response = await client.post("/typing/stop", json={
            "channel_id": ""
        })

        # This should fail validation or service logic
        assert response.status_code in [400, 422, 500]


class TestTypingAPIIntegrationWithWebRoutes:
    """Test typing API integration with web routes."""

    @pytest.fixture
    async def client(self):
        """Create test client with web routes."""
        from plexichat.interfaces.web.routes.collaboration.chat import router as chat_router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(chat_router, prefix="/api")

        async with AsyncClient(app=app, base_url="http://testserver") as client:
            yield client

    @pytest.mark.asyncio
    async def test_chat_route_start_typing(self, client):
        """Test typing start via chat routes."""
        # Mock the messaging system
        with patch('plexichat.interfaces.web.routes.collaboration.chat.get_messaging_system') as mock_get_ms:
            mock_ms = AsyncMock()
            mock_ms.handle_typing_start.return_value = True
            mock_get_ms.return_value = mock_ms

            response = await client.post("/api/typing/start", json={
                "user_id": "test_user",
                "channel_id": "test_channel"
            })

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["action"] == "typing_started"

    @pytest.mark.asyncio
    async def test_chat_route_stop_typing(self, client):
        """Test typing stop via chat routes."""
        with patch('plexichat.interfaces.web.routes.collaboration.chat.get_messaging_system') as mock_get_ms:
            mock_ms = AsyncMock()
            mock_ms.handle_typing_stop.return_value = True
            mock_get_ms.return_value = mock_ms

            response = await client.post("/api/typing/stop", json={
                "user_id": "test_user",
                "channel_id": "test_channel"
            })

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["action"] == "typing_stopped"

    @pytest.mark.asyncio
    async def test_chat_route_get_typing_users(self, client):
        """Test get typing users via chat routes."""
        with patch('plexichat.interfaces.web.routes.collaboration.chat.get_messaging_system') as mock_get_ms:
            mock_ms = AsyncMock()
            mock_ms.get_typing_users.return_value = ["user1", "user2"]
            mock_get_ms.return_value = mock_ms

            response = await client.get("/api/typing/test_channel")

            assert response.status_code == 200
            data = response.json()
            assert data["channel_id"] == "test_channel"
            assert data["typing_users"] == ["user1", "user2"]


class TestTypingAPIPerformance:
    """Test performance aspects of typing API endpoints."""

    @pytest.fixture
    async def client(self):
        """Create test client."""
        from plexichat.interfaces.api.v1.typing import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        async with AsyncClient(app=app, base_url="http://testserver") as client:
            yield client

    @pytest.mark.asyncio
    async def test_concurrent_typing_requests(self, client):
        """Test handling of concurrent typing requests."""
        # Mock typing service
        with patch.object(typing_service, 'start_typing', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = True

            # Send multiple concurrent requests
            tasks = []
            for i in range(10):
                task = asyncio.create_task(
                    client.post("/typing/start", json={
                        "channel_id": f"channel_{i}"
                    })
                )
                tasks.append(task)

            responses = await asyncio.gather(*tasks)

            # All should succeed
            assert all(r.status_code == 200 for r in responses)
            assert mock_start.call_count == 10

    @pytest.mark.asyncio
    async def test_api_response_time(self, client):
        """Test API response times are reasonable."""
        with patch.object(typing_service, 'get_typing_users', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = ["user1", "user2"]

            import time
            start_time = time.time()

            response = await client.get("/typing/status/test_channel")

            end_time = time.time()
            duration = end_time - start_time

            assert response.status_code == 200
            # Response should be fast (< 100ms)
            assert duration < 0.1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])