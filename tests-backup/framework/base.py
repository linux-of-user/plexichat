"""
Base test classes for PlexiChat testing framework.
"""

import asyncio
import unittest
import pytest
from typing import Any, Dict, List, Optional
from unittest.mock import Mock, patch, MagicMock
import tempfile
import shutil
from pathlib import Path


class BaseTest(unittest.TestCase):
    """Base test class with common utilities."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
        self.mocks = {}
        self.patches = []
        
    def tearDown(self):
        """Clean up test environment."""
        # Stop all patches
        for patcher in self.patches:
            patcher.stop()
        
        # Clean up temp directory
        if self.temp_path.exists():
            shutil.rmtree(self.temp_path)
    
    def create_mock(self, name: str, **kwargs) -> Mock:
        """Create and store a mock object."""
        mock = Mock(**kwargs)
        self.mocks[name] = mock
        return mock
    
    def patch_object(self, target: str, **kwargs) -> Mock:
        """Patch an object and store the patcher."""
        patcher = patch(target, **kwargs)
        mock = patcher.start()
        self.patches.append(patcher)
        return mock
    
    def create_temp_file(self, name: str, content: str = "") -> Path:
        """Create a temporary file."""
        file_path = self.temp_path / name
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)
        return file_path
    
    def assert_called_with_partial(self, mock: Mock, **kwargs):
        """Assert mock was called with partial arguments."""
        for call in mock.call_args_list:
            call_kwargs = call.kwargs if hasattr(call, 'kwargs') else {}
            if all(call_kwargs.get(k) == v for k, v in kwargs.items()):
                return
        
        self.fail(f"Mock was not called with {kwargs}")


class AsyncBaseTest(BaseTest):
    """Base test class for async tests."""
    
    def setUp(self):
        """Set up async test environment."""
        super().setUp()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
    
    def tearDown(self):
        """Clean up async test environment."""
        super().tearDown()
        self.loop.close()
    
    def run_async(self, coro):
        """Run an async coroutine in the test loop."""
        return self.loop.run_until_complete(coro)
    
    async def async_setUp(self):
        """Override for async setup."""
        pass
    
    async def async_tearDown(self):
        """Override for async teardown."""
        pass


class DatabaseTestMixin:
    """Mixin for database-related tests."""
    
    def setUp(self):
        """Set up database test environment."""
        super().setUp()
        self.db_mock = self.create_mock('database')
        self.db_session_mock = self.create_mock('db_session')
        
        # Mock database operations
        self.db_mock.get_session.return_value = self.db_session_mock
        self.db_session_mock.commit.return_value = None
        self.db_session_mock.rollback.return_value = None
        self.db_session_mock.close.return_value = None
    
    def mock_db_query(self, result: Any):
        """Mock database query result."""
        self.db_session_mock.query.return_value.filter.return_value.first.return_value = result
        return result
    
    def mock_db_add(self, obj: Any):
        """Mock database add operation."""
        self.db_session_mock.add.return_value = None
        return obj


class APITestMixin:
    """Mixin for API-related tests."""
    
    def setUp(self):
        """Set up API test environment."""
        super().setUp()
        self.client_mock = self.create_mock('api_client')
        self.response_mock = self.create_mock('response')
        
        # Default response
        self.response_mock.status_code = 200
        self.response_mock.json.return_value = {}
        self.client_mock.get.return_value = self.response_mock
        self.client_mock.post.return_value = self.response_mock
        self.client_mock.put.return_value = self.response_mock
        self.client_mock.delete.return_value = self.response_mock
    
    def mock_api_response(self, status_code: int = 200, data: Dict = None):
        """Mock API response."""
        self.response_mock.status_code = status_code
        self.response_mock.json.return_value = data or {}
        return self.response_mock
    
    def assert_api_called(self, method: str, url: str, **kwargs):
        """Assert API was called with specific parameters."""
        client_method = getattr(self.client_mock, method.lower())
        client_method.assert_called_with(url, **kwargs)


class SecurityTestMixin:
    """Mixin for security-related tests."""
    
    def setUp(self):
        """Set up security test environment."""
        super().setUp()
        self.auth_mock = self.create_mock('auth_manager')
        self.user_mock = self.create_mock('user')
        
        # Default authenticated user
        self.user_mock.id = "test_user_id"
        self.user_mock.username = "test_user"
        self.user_mock.role = "user"
        self.auth_mock.get_current_user.return_value = self.user_mock
    
    def mock_authenticated_user(self, user_data: Dict):
        """Mock authenticated user."""
        for key, value in user_data.items():
            setattr(self.user_mock, key, value)
        return self.user_mock
    
    def mock_unauthenticated(self):
        """Mock unauthenticated state."""
        self.auth_mock.get_current_user.return_value = None


class PerformanceTestMixin:
    """Mixin for performance-related tests."""
    
    def setUp(self):
        """Set up performance test environment."""
        super().setUp()
        self.performance_data = []
    
    def measure_time(self, func, *args, **kwargs):
        """Measure execution time of a function."""
        import time
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        execution_time = end_time - start_time
        self.performance_data.append({
            'function': func.__name__,
            'execution_time': execution_time,
            'args': args,
            'kwargs': kwargs
        })
        
        return result, execution_time
    
    def assert_performance_threshold(self, max_time: float):
        """Assert that all measured operations are within time threshold."""
        for data in self.performance_data:
            self.assertLess(
                data['execution_time'], 
                max_time,
                f"Function {data['function']} took {data['execution_time']:.3f}s, "
                f"exceeding threshold of {max_time}s"
            )


# Combined test classes
class DatabaseTest(DatabaseTestMixin, BaseTest):
    """Test class for database operations."""
    pass


class AsyncDatabaseTest(DatabaseTestMixin, AsyncBaseTest):
    """Async test class for database operations."""
    pass


class APITest(APITestMixin, BaseTest):
    """Test class for API operations."""
    pass


class AsyncAPITest(APITestMixin, AsyncBaseTest):
    """Async test class for API operations."""
    pass


class SecurityTest(SecurityTestMixin, BaseTest):
    """Test class for security operations."""
    pass


class PerformanceTest(PerformanceTestMixin, BaseTest):
    """Test class for performance testing."""
    pass


class IntegrationTest(DatabaseTestMixin, APITestMixin, SecurityTestMixin, BaseTest):
    """Test class for integration testing."""
    pass


class AsyncIntegrationTest(DatabaseTestMixin, APITestMixin, SecurityTestMixin, AsyncBaseTest):
    """Async test class for integration testing."""
    pass
