"""
Pytest configuration and fixtures for unit tests.
"""

import pytest
from unittest.mock import MagicMock, AsyncMock


@pytest.fixture
def mock_security_system():
    """Create mock security system for unit testing."""
    mock_system = MagicMock()
    mock_system.user_credentials = {}
    mock_system.token_manager = MagicMock()
    mock_system.password_manager = MagicMock()
    mock_system.authenticate_user = AsyncMock(return_value=(True, MagicMock(
        user_id="testuser",
        permissions={"read"}
    )))
    return mock_system


@pytest.fixture
def mock_database():
    """Create mock database for unit testing."""
    mock_db = MagicMock()
    mock_db.connect = AsyncMock(return_value=True)
    mock_db.disconnect = AsyncMock(return_value=True)
    mock_db.execute = AsyncMock(return_value=[])
    mock_db.fetchone = AsyncMock(return_value=None)
    mock_db.fetchall = AsyncMock(return_value=[])
    return mock_db


@pytest.fixture
def mock_redis():
    """Create mock Redis for unit testing."""
    mock_redis = MagicMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock(return_value=True)
    mock_redis.delete = AsyncMock(return_value=1)
    mock_redis.exists = AsyncMock(return_value=0)
    return mock_redis


@pytest.fixture
def mock_websocket_manager():
    """Create mock WebSocket manager for unit testing."""
    mock_ws = MagicMock()
    mock_ws.broadcast = AsyncMock(return_value=True)
    mock_ws.send_to_user = AsyncMock(return_value=True)
    mock_ws.get_active_connections = MagicMock(return_value=[])
    return mock_ws


@pytest.fixture
def mock_config():
    """Create mock configuration for unit testing."""
    mock_cfg = MagicMock()
    mock_cfg.get = MagicMock(return_value="test_value")
    mock_cfg.set = MagicMock(return_value=True)
    mock_cfg.reload = MagicMock(return_value=True)
    return mock_cfg


@pytest.fixture
def mock_logger():
    """Create mock logger for unit testing."""
    mock_log = MagicMock()
    mock_log.info = MagicMock()
    mock_log.error = MagicMock()
    mock_log.warning = MagicMock()
    mock_log.debug = MagicMock()
    return mock_log


@pytest.fixture
def mock_validator():
    """Create mock validator for unit testing."""
    mock_val = MagicMock()
    mock_val.validate = MagicMock(return_value=(True, []))
    mock_val.sanitize = MagicMock(return_value="sanitized_input")
    return mock_val


@pytest.fixture
def mock_cache():
    """Create mock cache for unit testing."""
    mock_cache = MagicMock()
    mock_cache.get = AsyncMock(return_value=None)
    mock_cache.set = AsyncMock(return_value=True)
    mock_cache.delete = AsyncMock(return_value=True)
    mock_cache.clear = AsyncMock(return_value=True)
    return mock_cache


@pytest.fixture
def mock_file_manager():
    """Create mock file manager for unit testing."""
    mock_fm = MagicMock()
    mock_fm.read_file = AsyncMock(return_value="file_content")
    mock_fm.write_file = AsyncMock(return_value=True)
    mock_fm.delete_file = AsyncMock(return_value=True)
    mock_fm.list_files = AsyncMock(return_value=[])
    return mock_fm


@pytest.fixture
def mock_notification_service():
    """Create mock notification service for unit testing."""
    mock_ns = MagicMock()
    mock_ns.send_email = AsyncMock(return_value=True)
    mock_ns.send_push = AsyncMock(return_value=True)
    mock_ns.send_sms = AsyncMock(return_value=True)
    return mock_ns


@pytest.fixture
def mock_plugin_manager():
    """Create mock plugin manager for unit testing."""
    mock_pm = MagicMock()
    mock_pm.load_plugin = AsyncMock(return_value=True)
    mock_pm.unload_plugin = AsyncMock(return_value=True)
    mock_pm.get_plugin = MagicMock(return_value=MagicMock())
    mock_pm.list_plugins = MagicMock(return_value=[])
    return mock_pm


@pytest.fixture
def mock_scheduler():
    """Create mock scheduler for unit testing."""
    mock_sched = MagicMock()
    mock_sched.add_job = MagicMock(return_value="job_id")
    mock_sched.remove_job = MagicMock(return_value=True)
    mock_sched.get_jobs = MagicMock(return_value=[])
    return mock_sched


@pytest.fixture
def mock_monitoring():
    """Create mock monitoring service for unit testing."""
    mock_mon = MagicMock()
    mock_mon.record_metric = MagicMock()
    mock_mon.get_metrics = MagicMock(return_value={})
    mock_mon.start_timer = MagicMock(return_value="timer_id")
    mock_mon.stop_timer = MagicMock(return_value=0.001)
    return mock_mon


@pytest.fixture
def mock_audit_logger():
    """Create mock audit logger for unit testing."""
    mock_audit = MagicMock()
    mock_audit.log_event = AsyncMock(return_value=True)
    mock_audit.get_events = AsyncMock(return_value=[])
    mock_audit.search_events = AsyncMock(return_value=[])
    return mock_audit


@pytest.fixture
def mock_rate_limiter():
    """Create mock rate limiter for unit testing."""
    mock_rl = MagicMock()
    mock_rl.check_limit = AsyncMock(return_value=(True, 0))
    mock_rl.record_request = AsyncMock(return_value=True)
    mock_rl.get_remaining = AsyncMock(return_value=100)
    return mock_rl


@pytest.fixture
def mock_encryption():
    """Create mock encryption service for unit testing."""
    mock_enc = MagicMock()
    mock_enc.encrypt = MagicMock(return_value="encrypted_data")
    mock_enc.decrypt = MagicMock(return_value="decrypted_data")
    mock_enc.hash_password = MagicMock(return_value=("hash", "salt"))
    mock_enc.verify_password = MagicMock(return_value=True)
    return mock_enc


@pytest.fixture
def mock_backup_service():
    """Create mock backup service for unit testing."""
    mock_bs = MagicMock()
    mock_bs.create_backup = AsyncMock(return_value="backup_id")
    mock_bs.restore_backup = AsyncMock(return_value=True)
    mock_bs.list_backups = AsyncMock(return_value=[])
    mock_bs.delete_backup = AsyncMock(return_value=True)
    return mock_bs


@pytest.fixture
def mock_migration_manager():
    """Create mock migration manager for unit testing."""
    mock_mm = MagicMock()
    mock_mm.create_migration = MagicMock(return_value="migration_id")
    mock_mm.run_migration = AsyncMock(return_value=True)
    mock_mm.rollback_migration = AsyncMock(return_value=True)
    mock_mm.get_migration_status = MagicMock(return_value="completed")
    return mock_mm


@pytest.fixture
def mock_health_checker():
    """Create mock health checker for unit testing."""
    mock_hc = MagicMock()
    mock_hc.check_database = AsyncMock(return_value=True)
    mock_hc.check_redis = AsyncMock(return_value=True)
    mock_hc.check_filesystem = AsyncMock(return_value=True)
    mock_hc.get_system_health = AsyncMock(return_value={"status": "healthy"})
    return mock_hc


@pytest.fixture
def mock_metrics_collector():
    """Create mock metrics collector for unit testing."""
    mock_mc = MagicMock()
    mock_mc.increment_counter = MagicMock()
    mock_mc.record_histogram = MagicMock()
    mock_mc.record_gauge = MagicMock()
    mock_mc.get_metrics = MagicMock(return_value={})
    return mock_mc


@pytest.fixture
def mock_feature_flag():
    """Create mock feature flag service for unit testing."""
    mock_ff = MagicMock()
    mock_ff.is_enabled = MagicMock(return_value=True)
    mock_ff.enable = MagicMock(return_value=True)
    mock_ff.disable = MagicMock(return_value=True)
    mock_ff.get_flags = MagicMock(return_value=[])
    return mock_ff