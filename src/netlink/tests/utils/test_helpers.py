"""Test helper utilities."""
import asyncio
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

class TestHelper:
    """Synchronous test helper utilities."""
    
    @staticmethod
    def create_test_user(username: str = "testuser") -> Dict[str, Any]:
        """Create a test user."""
        return {
            "username": username,
            "email": f"{username}@test.com",
            "password": "testpassword123",
            "is_active": True
        }
    
    @staticmethod
    def create_test_message(content: str = "Test message") -> Dict[str, Any]:
        """Create a test message."""
        return {
            "content": content,
            "user_id": "testuser",
            "timestamp": "2024-01-01T00:00:00Z"
        }

class AsyncTestHelper:
    """Asynchronous test helper utilities."""
    
    @staticmethod
    async def wait_for_condition(condition_func, timeout: float = 5.0, interval: float = 0.1) -> bool:
        """Wait for a condition to become true."""
        elapsed = 0.0
        while elapsed < timeout:
            if await condition_func():
                return True
            await asyncio.sleep(interval)
            elapsed += interval
        return False
    
    @staticmethod
    async def simulate_async_operation(duration: float = 0.1) -> str:
        """Simulate an async operation."""
        await asyncio.sleep(duration)
        return "operation_complete"
