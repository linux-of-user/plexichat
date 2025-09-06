"""
Shared pytest fixtures and configuration for PlexiChat tests.
"""

print("DEBUG: Starting conftest.py imports")

import asyncio
import pytest
import tempfile
import os
from unittest.mock import MagicMock, AsyncMock
from typing import Dict, Any, List, Optional
import json

print("DEBUG: Basic imports completed")

try:
    from plexichat.core.database.manager import DatabaseManager, DatabaseConfig, DatabaseSession
    print("DEBUG: Database imports successful")
except Exception as e:
    print(f"DEBUG: Database import failed: {e}")

try:
    from plexichat.core.caching.unified_cache_integration import UnifiedCacheManager
    print("DEBUG: Cache imports successful")
except Exception as e:
    print(f"DEBUG: Cache import failed: {e}")

try:
    from plexichat.core.orchestrator import SystemOrchestrator, ModuleManager, ComponentRegistry
    print("DEBUG: Orchestrator imports successful")
except Exception as e:
    print(f"DEBUG: Orchestrator import failed: {e}")

try:
    from plexichat.core.authentication import UnifiedAuthManager, SessionInfo, AuthResult
    print("DEBUG: Authentication imports successful")
except Exception as e:
    print(f"DEBUG: Authentication import failed: {e}")

print("DEBUG: All imports completed")


# Database Fixtures
print("DEBUG: Defining database fixtures")

@pytest.fixture
def sqlite_config():
    """SQLite database configuration for testing."""
    print("DEBUG: Creating sqlite_config fixture")
    return DatabaseConfig(
        db_type="sqlite",
        path=":memory:",
        pool_size=5,
        max_overflow=10
    )


@pytest.fixture
def postgres_config():
    """PostgreSQL database configuration for testing."""
    return DatabaseConfig(
        db_type="postgresql",
        host="localhost",
        port=5432,
        name="plexichat_test",
        username="test_user",
        password="test_password"
    )


@pytest.fixture
def mysql_config():
    """MySQL database configuration for testing."""
    return DatabaseConfig(
        db_type="mysql",
        host="localhost",
        port=3306,
        name="plexichat_test",
        username="test_user",
        password="test_password"
    )


@pytest.fixture
def mock_database_session():
    """Mock database session for testing."""
    session = MagicMock(spec=DatabaseSession)

    # Mock async methods
    session.execute = AsyncMock()
    session.fetchall = AsyncMock()
    session.fetchone = AsyncMock()
    session.insert = AsyncMock()
    session.update = AsyncMock()
    session.delete = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.close = AsyncMock()

    return session


@pytest.fixture
async def mock_database_manager(sqlite_config, mock_database_session):
    """Mock database manager for testing."""
    manager = MagicMock(spec=DatabaseManager)
    manager.config = sqlite_config
    manager.get_session = AsyncMock()
    manager.get_session.return_value.__aenter__ = AsyncMock(return_value=mock_database_session)
    manager.get_session.return_value.__aexit__ = AsyncMock(return_value=None)
    manager.initialize = AsyncMock(return_value=True)
    manager.health_check = AsyncMock(return_value=True)
    manager.ensure_table_exists = AsyncMock(return_value=True)

    return manager


# Cache Fixtures
@pytest.fixture
def cache_config():
    """Cache configuration for testing."""
    return {
        "max_memory_size": 1000,
        "default_ttl_seconds": 300,
        "strategy": "lru",
        "compression_enabled": False,
        "serialization_format": "json"
    }


@pytest.fixture
def redis_cache_config():
    """Redis cache configuration for testing."""
    return {
        "max_memory_size": 1000,
        "default_ttl_seconds": 300,
        "l2_redis_enabled": True,
        "l2_redis_host": "localhost",
        "l2_redis_port": 6379,
        "l2_redis_db": 1
    }


@pytest.fixture
async def mock_cache_manager(cache_config):
    """Mock cache manager for testing."""
    manager = MagicMock(spec=UnifiedCacheManager)
    manager.config = cache_config
    manager.get = AsyncMock(return_value=None)
    manager.set = AsyncMock(return_value=True)
    manager.delete = AsyncMock(return_value=True)
    manager.clear = AsyncMock(return_value=True)
    manager.get_stats = AsyncMock(return_value={
        "hits": 0,
        "misses": 0,
        "sets": 0,
        "deletes": 0,
        "evictions": 0,
        "hit_rate": 0.0,
        "memory_entries": 0,
        "memory_usage_percent": 0.0
    })
    manager.initialize = AsyncMock()
    manager.shutdown = AsyncMock()

    return manager


@pytest.fixture
async def mock_redis_cache_manager(redis_cache_config):
    """Mock Redis-enabled cache manager."""
    manager = MagicMock(spec=UnifiedCacheManager)
    manager.config = redis_cache_config
    manager.redis_client = MagicMock()
    manager.redis_client.get = AsyncMock(return_value=None)
    manager.redis_client.setex = AsyncMock(return_value=True)
    manager.redis_client.delete = AsyncMock(return_value=True)
    manager.redis_client.flushdb = AsyncMock(return_value=True)

    return manager


# Authentication Fixtures
@pytest.fixture
def mock_security_system():
    """Mock security system for testing."""
    security_system = MagicMock()
    security_system.authenticate_user = AsyncMock(return_value=(True, MagicMock(user_id="test_user")))
    security_system.token_manager = MagicMock()
    security_system.token_manager.create_access_token = MagicMock(return_value="access_token_123")
    security_system.token_manager.create_refresh_token = MagicMock(return_value="refresh_token_456")
    security_system.token_manager.verify_token = MagicMock(return_value=(True, {"user_id": "test_user"}))
    security_system.user_credentials = {}
    security_system.password_manager = MagicMock()
    security_system.password_manager.hash_password = MagicMock(return_value=("hashed_pass", "salt"))
    security_system.password_manager.validate_password_strength = MagicMock(return_value=(True, []))

    return security_system


@pytest.fixture
def auth_manager(mock_security_system):
    """UnifiedAuthManager instance for testing."""
    return UnifiedAuthManager(mock_security_system)


@pytest.fixture
def sample_user():
    """Sample user data for testing."""
    return {
        "id": "user123",
        "username": "testuser",
        "email": "test@example.com",
        "display_name": "Test User",
        "is_active": True,
        "is_admin": False,
        "created_at": "2023-01-01T00:00:00Z",
        "updated_at": "2023-01-01T00:00:00Z"
    }


@pytest.fixture
def sample_session(sample_user):
    """Sample session data for testing."""
    return SessionInfo(
        session_id="session123",
        user_id=sample_user["id"],
        created_at=MagicMock(),
        last_accessed=MagicMock(),
        expires_at=MagicMock(),
        permissions={"read", "write"},
        roles=set(),
        ip_address="192.168.1.1",
        user_agent="Test Browser",
        is_active=True
    )


@pytest.fixture
def sample_auth_result(sample_user):
    """Sample authentication result for testing."""
    return AuthResult(
        success=True,
        user_id=sample_user["id"],
        session_id="session123",
        token="access_token",
        refresh_token="refresh_token",
        permissions={"read", "write"},
        roles=set(),
        auth_provider=MagicMock()
    )


# Orchestrator Fixtures
@pytest.fixture
def module_manager():
    """ModuleManager instance for testing."""
    return ModuleManager()


@pytest.fixture
def component_registry():
    """ComponentRegistry instance for testing."""
    return ComponentRegistry()


@pytest.fixture
def system_orchestrator(module_manager):
    """SystemOrchestrator instance for testing."""
    orchestrator = SystemOrchestrator()
    orchestrator.module_manager = module_manager
    return orchestrator


# Service Fixtures
@pytest.fixture
async def mock_message_service(mock_database_manager, mock_cache_manager):
    """Mock message service for testing."""
    service = MagicMock()
    service.db_manager = mock_database_manager
    service.cache_manager = mock_cache_manager
    service.send_message = AsyncMock(return_value={"message_id": "msg123"})
    service.get_messages = AsyncMock(return_value=[])
    service.add_reaction = AsyncMock(return_value=True)
    service.get_health_status = AsyncMock(return_value={"status": "healthy"})

    return service


@pytest.fixture
async def mock_user_service(mock_database_manager, mock_security_system):
    """Mock user service for testing."""
    service = MagicMock()
    service.db_manager = mock_database_manager
    service.security_service = mock_security_system
    service.create_user = AsyncMock(return_value={"user_id": "user123"})
    service.authenticate_user = AsyncMock(return_value={"authenticated": True, "user_id": "user123"})
    service.update_user_profile = AsyncMock(return_value={"success": True})
    service.get_user = AsyncMock(return_value={"id": "user123", "username": "testuser"})

    return service


@pytest.fixture
async def mock_security_service(mock_database_manager, mock_cache_manager):
    """Mock security service for testing."""
    service = MagicMock()
    service.db_manager = mock_database_manager
    service.cache_manager = mock_cache_manager
    service.check_user_permission = AsyncMock(return_value=True)
    service.log_audit_event = AsyncMock(return_value={"audit_id": "audit123"})

    return service


# Test Data Fixtures
@pytest.fixture
def sample_message():
    """Sample message data for testing."""
    return {
        "id": "msg123",
        "content": "Hello, World!",
        "user_id": "user123",
        "channel_id": "channel123",
        "message_type": "text",
        "created_at": "2023-01-01T12:00:00Z",
        "updated_at": "2023-01-01T12:00:00Z",
        "attachments": [],
        "reactions": {},
        "metadata": {}
    }


@pytest.fixture
def sample_channel():
    """Sample channel data for testing."""
    return {
        "id": "channel123",
        "name": "general",
        "description": "General discussion",
        "channel_type": "public",
        "owner_id": "user123",
        "members": ["user123", "user456"],
        "created_at": "2023-01-01T00:00:00Z",
        "updated_at": "2023-01-01T00:00:00Z"
    }


@pytest.fixture
def sample_workspace():
    """Sample workspace data for testing."""
    return {
        "id": "workspace123",
        "name": "Test Workspace",
        "description": "A test workspace",
        "owner_id": "user123",
        "members": ["user123"],
        "channels": ["channel123"],
        "created_at": "2023-01-01T00:00:00Z",
        "updated_at": "2023-01-01T00:00:00Z"
    }


@pytest.fixture
def sample_plugin():
    """Sample plugin data for testing."""
    return {
        "id": "plugin123",
        "name": "test_plugin",
        "version": "1.0.0",
        "description": "A test plugin",
        "author": "Test Author",
        "plugin_type": "feature",
        "status": "active",
        "config": {},
        "created_at": "2023-01-01T00:00:00Z",
        "updated_at": "2023-01-01T00:00:00Z"
    }


# Performance Testing Fixtures
@pytest.fixture
def performance_config():
    """Configuration for performance testing."""
    return {
        "enable_performance_logging": True,
        "performance_log_level": "INFO",
        "metrics_collection_interval": 60,
        "slow_query_threshold_ms": 1000
    }


@pytest.fixture
def load_test_config():
    """Configuration for load testing."""
    return {
        "concurrent_users": 100,
        "test_duration_seconds": 300,
        "ramp_up_period_seconds": 60,
        "think_time_seconds": 2,
        "max_response_time_ms": 5000
    }


# Error Simulation Fixtures
@pytest.fixture
def database_error():
    """Simulated database error."""
    return Exception("Database connection failed")


@pytest.fixture
def cache_error():
    """Simulated cache error."""
    return Exception("Cache service unavailable")


@pytest.fixture
def network_error():
    """Simulated network error."""
    return Exception("Network timeout")


@pytest.fixture
def authentication_error():
    """Simulated authentication error."""
    return Exception("Invalid credentials")


# Cleanup Fixtures
@pytest.fixture(autouse=True)
def cleanup_after_test():
    """Cleanup after each test."""
    yield
    # Add any cleanup logic here
    # For example, clearing caches, closing connections, etc.


# Event Loop Fixture for async tests
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# Temporary Directory Fixture
@pytest.fixture
def temp_dir():
    """Temporary directory for file-based tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def temp_db_path(temp_dir):
    """Temporary database file path."""
    return os.path.join(temp_dir, "test.db")


# JSON Test Data
@pytest.fixture
def json_test_data():
    """JSON test data for serialization tests."""
    return {
        "users": [
            {"id": "user1", "name": "Alice", "role": "admin"},
            {"id": "user2", "name": "Bob", "role": "user"},
            {"id": "user3", "name": "Charlie", "role": "user"}
        ],
        "messages": [
            {"id": "msg1", "user_id": "user1", "content": "Hello!"},
            {"id": "msg2", "user_id": "user2", "content": "Hi there!"}
        ],
        "channels": [
            {"id": "chan1", "name": "general", "type": "public"},
            {"id": "chan2", "name": "random", "type": "public"}
        ]
    }


# Binary Test Data
@pytest.fixture
def binary_test_data():
    """Binary test data for serialization tests."""
    return {
        "image_data": b"fake_image_bytes_12345",
        "file_content": b"fake_file_content_abcdef",
        "binary_payload": b"binary_payload_data_98765"
    }


# Mock External Services
@pytest.fixture
def mock_redis_client():
    """Mock Redis client for testing."""
    client = MagicMock()
    client.get = AsyncMock(return_value=None)
    client.set = AsyncMock(return_value=True)
    client.setex = AsyncMock(return_value=True)
    client.delete = AsyncMock(return_value=True)
    client.exists = AsyncMock(return_value=True)
    client.expire = AsyncMock(return_value=True)
    client.ttl = AsyncMock(return_value=300)
    client.flushdb = AsyncMock(return_value=True)
    client.ping = AsyncMock(return_value=True)

    return client


@pytest.fixture
def mock_postgres_connection():
    """Mock PostgreSQL connection for testing."""
    conn = MagicMock()
    conn.execute = AsyncMock()
    conn.fetch = AsyncMock(return_value=[])
    conn.fetchrow = AsyncMock(return_value=None)
    conn.close = AsyncMock()
    conn.is_closed = False

    return conn


@pytest.fixture
def mock_mysql_connection():
    """Mock MySQL connection for testing."""
    conn = MagicMock()
    conn.execute = AsyncMock()
    conn.fetchall = AsyncMock(return_value=[])
    conn.fetchone = AsyncMock(return_value=None)
    conn.close = AsyncMock()
    conn.ping = AsyncMock(return_value=True)

    return conn


# Test Configuration
def pytest_configure(config):
    """Pytest configuration hook."""
    # Add custom markers
    config.addinivalue_line("markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "performance: marks tests as performance tests")
    config.addinivalue_line("markers", "redis: marks tests that require Redis")
    config.addinivalue_line("markers", "postgres: marks tests that require PostgreSQL")
    config.addinivalue_line("markers", "mysql: marks tests that require MySQL")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names."""
    for item in items:
        # Mark integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Mark performance tests
        if "performance" in item.name or "load" in item.name:
            item.add_marker(pytest.mark.performance)

        # Mark database-specific tests
        if "postgres" in item.name:
            item.add_marker(pytest.mark.postgres)
        elif "mysql" in item.name:
            item.add_marker(pytest.mark.mysql)
        elif "redis" in item.name:
            item.add_marker(pytest.mark.redis)


# Custom assertion helpers
def assert_cache_hit(cache_manager, key, expected_value):
    """Assert that a cache key contains the expected value."""
    result = asyncio.run(cache_manager.get(key))
    assert result == expected_value, f"Cache miss or wrong value for key {key}"


def assert_cache_miss(cache_manager, key):
    """Assert that a cache key is not present."""
    result = asyncio.run(cache_manager.get(key))
    assert result is None, f"Unexpected cache hit for key {key}"


def assert_database_row_count(session, table_name, expected_count):
    """Assert the number of rows in a database table."""
    # This would need to be implemented based on the actual database session interface
    pass


def assert_service_healthy(service, expected_status="healthy"):
    """Assert that a service is in a healthy state."""
    if hasattr(service, 'get_health_status'):
        status = asyncio.run(service.get_health_status())
        assert status.get("status") == expected_status


# Performance assertion helpers
def assert_response_time(func, max_time_ms):
    """Assert that a function completes within the specified time."""
    import time
    start_time = time.time()
    result = func()
    end_time = time.time()
    duration_ms = (end_time - start_time) * 1000

    assert duration_ms <= max_time_ms, f"Function took {duration_ms}ms, expected <= {max_time_ms}ms"
    return result


async def assert_async_response_time(coro, max_time_ms):
    """Assert that an async function completes within the specified time."""
    import time
    start_time = time.time()
    result = await coro
    end_time = time.time()
    duration_ms = (end_time - start_time) * 1000

    assert duration_ms <= max_time_ms, f"Async function took {duration_ms}ms, expected <= {max_time_ms}ms"
    return result

print("DEBUG: conftest.py loaded successfully")