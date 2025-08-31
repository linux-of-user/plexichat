"""
Pytest configuration and fixtures for integration tests.
"""

import pytest
from unittest.mock import MagicMock, AsyncMock


@pytest.fixture
def mock_database_pool():
    """Create mock database connection pool for integration testing."""
    mock_pool = MagicMock()
    mock_pool.acquire = AsyncMock()
    mock_pool.release = AsyncMock()
    mock_pool.close = AsyncMock()
    mock_pool.get_stats = MagicMock(return_value={
        "active_connections": 5,
        "idle_connections": 10,
        "total_connections": 15
    })
    return mock_pool


@pytest.fixture
def mock_database_connection():
    """Create mock database connection for integration testing."""
    mock_conn = MagicMock()
    mock_conn.execute = AsyncMock(return_value=MagicMock(
        rowcount=1,
        lastrowid=123
    ))
    mock_conn.fetchone = AsyncMock(return_value={"id": 1, "name": "test"})
    mock_conn.fetchall = AsyncMock(return_value=[
        {"id": 1, "name": "test1"},
        {"id": 2, "name": "test2"}
    ])
    mock_conn.commit = AsyncMock()
    mock_conn.rollback = AsyncMock()
    return mock_conn


@pytest.fixture
def mock_redis_client():
    """Create mock Redis client for integration testing."""
    mock_client = MagicMock()
    mock_client.connect = AsyncMock(return_value=True)
    mock_client.disconnect = AsyncMock(return_value=True)
    mock_client.ping = AsyncMock(return_value=True)
    mock_client.info = AsyncMock(return_value={"redis_version": "7.0.0"})
    return mock_client


@pytest.fixture
def mock_websocket_manager():
    """Create mock WebSocket manager for integration testing."""
    mock_ws = MagicMock()
    mock_ws.broadcast = AsyncMock(return_value=True)
    mock_ws.send_to_user = AsyncMock(return_value=True)
    mock_ws.get_active_connections = MagicMock(return_value=[])
    mock_ws.handle_connection = AsyncMock(return_value="connection_id")
    mock_ws.handle_disconnection = AsyncMock(return_value=True)
    return mock_ws


@pytest.fixture
def mock_message_queue():
    """Create mock message queue for integration testing."""
    mock_mq = MagicMock()
    mock_mq.publish = AsyncMock(return_value=True)
    mock_mq.subscribe = AsyncMock(return_value=True)
    mock_mq.unsubscribe = AsyncMock(return_value=True)
    mock_mq.get_message = AsyncMock(return_value={"type": "test", "data": "message"})
    return mock_mq


@pytest.fixture
def mock_cache_service():
    """Create mock cache service for integration testing."""
    mock_cache = MagicMock()
    mock_cache.get = AsyncMock(return_value="cached_value")
    mock_cache.set = AsyncMock(return_value=True)
    mock_cache.delete = AsyncMock(return_value=True)
    mock_cache.exists = AsyncMock(return_value=True)
    mock_cache.flush = AsyncMock(return_value=True)
    return mock_cache


@pytest.fixture
def mock_session_store():
    """Create mock session store for integration testing."""
    mock_store = MagicMock()
    mock_store.create_session = AsyncMock(return_value="session_123")
    mock_store.get_session = AsyncMock(return_value={"user_id": "user1", "data": "test"})
    mock_store.update_session = AsyncMock(return_value=True)
    mock_store.delete_session = AsyncMock(return_value=True)
    mock_store.session_exists = AsyncMock(return_value=True)
    return mock_store


@pytest.fixture
def mock_pubsub_client():
    """Create mock pub/sub client for integration testing."""
    mock_client = MagicMock()
    mock_client.publish = AsyncMock(return_value=5)
    mock_client.subscribe = AsyncMock(return_value=True)
    mock_client.unsubscribe = AsyncMock(return_value=True)
    mock_client.get_message = AsyncMock(return_value={
        "type": "message",
        "channel": "test_channel",
        "data": "test_message"
    })
    return mock_client


@pytest.fixture
def mock_api_client():
    """Create mock API client for integration testing."""
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value={"status": "success", "data": []})
    mock_client.post = AsyncMock(return_value={"status": "created", "id": 123})
    mock_client.put = AsyncMock(return_value={"status": "updated"})
    mock_client.delete = AsyncMock(return_value={"status": "deleted"})
    return mock_client


@pytest.fixture
def mock_file_storage():
    """Create mock file storage for integration testing."""
    mock_storage = MagicMock()
    mock_storage.upload = AsyncMock(return_value="file_id_123")
    mock_storage.download = AsyncMock(return_value=b"file_content")
    mock_storage.delete = AsyncMock(return_value=True)
    mock_storage.list_files = AsyncMock(return_value=["file1.txt", "file2.txt"])
    return mock_storage


@pytest.fixture
def mock_notification_service():
    """Create mock notification service for integration testing."""
    mock_ns = MagicMock()
    mock_ns.send_email = AsyncMock(return_value=True)
    mock_ns.send_push = AsyncMock(return_value=True)
    mock_ns.send_sms = AsyncMock(return_value=True)
    mock_ns.get_delivery_status = AsyncMock(return_value="delivered")
    return mock_ns


@pytest.fixture
def mock_metrics_collector():
    """Create mock metrics collector for integration testing."""
    mock_mc = MagicMock()
    mock_mc.record_request = AsyncMock()
    mock_mc.record_error = AsyncMock()
    mock_mc.get_metrics = AsyncMock(return_value={
        "requests_total": 1000,
        "errors_total": 5,
        "avg_response_time": 0.150
    })
    return mock_mc


@pytest.fixture
def mock_health_checker():
    """Create mock health checker for integration testing."""
    mock_hc = MagicMock()
    mock_hc.check_database = AsyncMock(return_value=True)
    mock_hc.check_redis = AsyncMock(return_value=True)
    mock_hc.check_websocket = AsyncMock(return_value=True)
    mock_hc.get_overall_health = AsyncMock(return_value={
        "status": "healthy",
        "checks": {
            "database": "healthy",
            "redis": "healthy",
            "websocket": "healthy"
        }
    })
    return mock_hc


@pytest.fixture
def mock_rate_limiter():
    """Create mock rate limiter for integration testing."""
    mock_rl = MagicMock()
    mock_rl.check_limit = AsyncMock(return_value=(True, 0))
    mock_rl.record_request = AsyncMock(return_value=True)
    mock_rl.get_remaining = AsyncMock(return_value=100)
    mock_rl.reset_limits = AsyncMock(return_value=True)
    return mock_rl


@pytest.fixture
def mock_backup_service():
    """Create mock backup service for integration testing."""
    mock_bs = MagicMock()
    mock_bs.create_backup = AsyncMock(return_value="backup_123")
    mock_bs.restore_backup = AsyncMock(return_value=True)
    mock_bs.list_backups = AsyncMock(return_value=[
        {"id": "backup_123", "created_at": "2023-12-01T10:00:00Z", "size": 1048576}
    ])
    mock_bs.delete_backup = AsyncMock(return_value=True)
    return mock_bs


@pytest.fixture
def mock_migration_manager():
    """Create mock migration manager for integration testing."""
    mock_mm = MagicMock()
    mock_mm.create_migration = MagicMock(return_value="migration_001")
    mock_mm.run_migration = AsyncMock(return_value=True)
    mock_mm.rollback_migration = AsyncMock(return_value=True)
    mock_mm.get_migration_status = MagicMock(return_value="completed")
    return mock_mm


@pytest.fixture
def mock_plugin_manager():
    """Create mock plugin manager for integration testing."""
    mock_pm = MagicMock()
    mock_pm.load_plugin = AsyncMock(return_value=True)
    mock_pm.unload_plugin = AsyncMock(return_value=True)
    mock_pm.get_plugin = MagicMock(return_value=MagicMock())
    mock_pm.list_plugins = MagicMock(return_value=["plugin1", "plugin2"])
    mock_pm.execute_plugin = AsyncMock(return_value={"result": "success"})
    return mock_pm


@pytest.fixture
def mock_audit_logger():
    """Create mock audit logger for integration testing."""
    mock_audit = MagicMock()
    mock_audit.log_event = AsyncMock(return_value=True)
    mock_audit.get_events = AsyncMock(return_value=[
        {"timestamp": "2023-12-01T10:00:00Z", "event": "user_login", "user": "user1"}
    ])
    mock_audit.search_events = AsyncMock(return_value=[])
    return mock_audit


@pytest.fixture
def mock_encryption_service():
    """Create mock encryption service for integration testing."""
    mock_enc = MagicMock()
    mock_enc.encrypt = MagicMock(return_value="encrypted_data")
    mock_enc.decrypt = MagicMock(return_value="decrypted_data")
    mock_enc.hash_password = MagicMock(return_value=("hash", "salt"))
    mock_enc.verify_password = MagicMock(return_value=True)
    return mock_enc


@pytest.fixture
def mock_feature_flag_service():
    """Create mock feature flag service for integration testing."""
    mock_ff = MagicMock()
    mock_ff.is_enabled = MagicMock(return_value=True)
    mock_ff.enable = MagicMock(return_value=True)
    mock_ff.disable = MagicMock(return_value=True)
    mock_ff.get_flags = MagicMock(return_value=[
        {"name": "new_feature", "enabled": True, "percentage": 100}
    ])
    return mock_ff