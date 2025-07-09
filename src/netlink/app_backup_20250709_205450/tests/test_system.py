"""
Comprehensive tests for system monitoring and management endpoints.
Tests system info, resource monitoring, health checks, and admin functions.
"""

import pytest
import json
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
from sqlmodel import Session, create_engine, SQLModel
from sqlmodel.pool import StaticPool

from app.main import app
from app.db import get_session
from app.models.user import User
from app.utils.auth import create_access_token

# Test database setup
@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session

@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session
    
    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()

@pytest.fixture(name="admin_user")
def admin_user_fixture(session: Session):
    user = User(
        username="admin",
        email="admin@example.com",
        hashed_password="hashed_password",
        is_admin=True
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@pytest.fixture(name="regular_user")
def regular_user_fixture(session: Session):
    user = User(
        username="user",
        email="user@example.com",
        hashed_password="hashed_password",
        is_admin=False
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@pytest.fixture(name="admin_headers")
def admin_headers_fixture(admin_user: User):
    token = create_access_token({"sub": admin_user.username})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(name="user_headers")
def user_headers_fixture(regular_user: User):
    token = create_access_token({"sub": regular_user.username})
    return {"Authorization": f"Bearer {token}"}

class TestSystemInfo:
    """Test system information endpoints."""
    
    @patch('app.routers.system.platform')
    @patch('app.routers.system.psutil')
    def test_get_system_info_success(self, mock_psutil, mock_platform, client: TestClient, admin_headers: dict):
        """Test successful system info retrieval."""
        # Mock platform information
        mock_platform.node.return_value = "test-server"
        mock_platform.system.return_value = "Linux"
        mock_platform.version.return_value = "5.4.0"
        mock_platform.architecture.return_value = ("x86_64", "")
        mock_platform.processor.return_value = "Intel Core i7"
        mock_platform.python_version.return_value = "3.9.0"
        
        # Mock psutil
        mock_psutil.boot_time.return_value = 1640995200.0  # 2022-01-01 00:00:00
        
        response = client.get("/v1/system/info", headers=admin_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["hostname"] == "test-server"
        assert data["platform"] == "Linux"
        assert data["architecture"] == "x86_64"
        assert "uptime_seconds" in data
        assert "boot_time" in data
    
    def test_get_system_info_unauthorized(self, client: TestClient, user_headers: dict):
        """Test system info access without admin privileges."""
        response = client.get("/v1/system/info", headers=user_headers)
        assert response.status_code == 403
    
    def test_get_system_info_no_auth(self, client: TestClient):
        """Test system info access without authentication."""
        response = client.get("/v1/system/info")
        assert response.status_code == 401

class TestResourceUsage:
    """Test resource usage monitoring."""
    
    @patch('app.routers.system.psutil')
    def test_get_resource_usage_success(self, mock_psutil, client: TestClient, admin_headers: dict):
        """Test successful resource usage retrieval."""
        # Mock CPU info
        mock_psutil.cpu_percent.return_value = 45.5
        mock_psutil.cpu_count.return_value = 8
        mock_cpu_freq = MagicMock()
        mock_cpu_freq._asdict.return_value = {"current": 2400.0, "min": 800.0, "max": 3200.0}
        mock_psutil.cpu_freq.return_value = mock_cpu_freq
        
        # Mock memory info
        mock_memory = MagicMock()
        mock_memory.total = 16 * 1024**3  # 16GB
        mock_memory.available = 8 * 1024**3  # 8GB
        mock_memory.percent = 50.0
        mock_psutil.virtual_memory.return_value = mock_memory
        
        # Mock disk info
        mock_disk = MagicMock()
        mock_disk.total = 1024**4  # 1TB
        mock_disk.used = 512 * 1024**3  # 512GB
        mock_disk.free = 512 * 1024**3  # 512GB
        mock_psutil.disk_usage.return_value = mock_disk
        
        # Mock network I/O
        mock_net_io = MagicMock()
        mock_net_io.bytes_sent = 1024**3
        mock_net_io.bytes_recv = 2 * 1024**3
        mock_net_io.packets_sent = 1000000
        mock_net_io.packets_recv = 2000000
        mock_psutil.net_io_counters.return_value = mock_net_io
        
        # Mock disk I/O
        mock_disk_io = MagicMock()
        mock_disk_io.read_bytes = 1024**3
        mock_disk_io.write_bytes = 512 * 1024**2
        mock_disk_io.read_count = 50000
        mock_disk_io.write_count = 25000
        mock_psutil.disk_io_counters.return_value = mock_disk_io
        
        response = client.get("/v1/system/resources", headers=admin_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["cpu_percent"] == 45.5
        assert data["cpu_count"] == 8
        assert data["memory_percent"] == 50.0
        assert data["disk_percent"] == 50.0
        assert "network_io" in data
        assert "disk_io" in data
    
    def test_get_resource_usage_unauthorized(self, client: TestClient, user_headers: dict):
        """Test resource usage access without admin privileges."""
        response = client.get("/v1/system/resources", headers=user_headers)
        assert response.status_code == 403

class TestProcessInfo:
    """Test process information endpoints."""
    
    @patch('app.routers.system.psutil')
    def test_get_processes_success(self, mock_psutil, client: TestClient, admin_headers: dict):
        """Test successful process information retrieval."""
        # Mock process data
        mock_proc1 = MagicMock()
        mock_proc1.info = {
            'pid': 1234,
            'name': 'python',
            'status': 'running',
            'cpu_percent': 15.5,
            'memory_percent': 8.2,
            'memory_info': MagicMock(rss=100*1024*1024, vms=200*1024*1024),
            'create_time': 1640995200.0,
            'cmdline': ['python', 'app.py']
        }
        mock_proc1.connections.return_value = [MagicMock(), MagicMock()]  # 2 connections
        
        mock_proc2 = MagicMock()
        mock_proc2.info = {
            'pid': 5678,
            'name': 'nginx',
            'status': 'running',
            'cpu_percent': 5.1,
            'memory_percent': 2.3,
            'memory_info': MagicMock(rss=50*1024*1024, vms=100*1024*1024),
            'create_time': 1640995300.0,
            'cmdline': ['nginx', '-g', 'daemon off;']
        }
        mock_proc2.connections.return_value = [MagicMock()]  # 1 connection
        
        mock_psutil.process_iter.return_value = [mock_proc1, mock_proc2]
        
        response = client.get("/v1/system/processes?limit=10", headers=admin_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["name"] == "python"
        assert data[0]["pid"] == 1234
        assert data[0]["connections"] == 2
        assert data[1]["name"] == "nginx"
    
    def test_get_processes_with_sorting(self, client: TestClient, admin_headers: dict):
        """Test process listing with different sorting options."""
        with patch('app.routers.system.psutil') as mock_psutil:
            # Mock minimal process data for sorting test
            mock_proc = MagicMock()
            mock_proc.info = {
                'pid': 1234,
                'name': 'test',
                'status': 'running',
                'cpu_percent': 10.0,
                'memory_percent': 5.0,
                'memory_info': MagicMock(rss=1024*1024, vms=2*1024*1024),
                'create_time': 1640995200.0,
                'cmdline': ['test']
            }
            mock_proc.connections.return_value = []
            mock_psutil.process_iter.return_value = [mock_proc]
            
            # Test different sort options
            for sort_by in ["cpu_percent", "memory_percent", "name", "pid"]:
                response = client.get(f"/v1/system/processes?sort_by={sort_by}", headers=admin_headers)
                assert response.status_code == 200

class TestLogStats:
    """Test log statistics endpoints."""
    
    @patch('app.routers.system.logging_manager')
    @patch('app.routers.system.Path')
    def test_get_log_stats_success(self, mock_path, mock_logging_manager, client: TestClient, admin_headers: dict):
        """Test successful log statistics retrieval."""
        # Mock logging manager
        mock_logs = [
            {'level': 'INFO', 'timestamp': '2022-01-01T12:00:00', 'message': 'Test info'},
            {'level': 'ERROR', 'timestamp': '2022-01-01T12:01:00', 'message': 'Test error', 'module': 'test'},
            {'level': 'DEBUG', 'timestamp': '2022-01-01T12:02:00', 'message': 'Test debug'}
        ]
        mock_logging_manager.get_recent_logs.return_value = mock_logs
        
        # Mock stream handler
        mock_stream_handler = MagicMock()
        mock_stream_handler.buffer = mock_logs
        mock_stream_handler.subscribers = set()
        mock_logging_manager.get_stream_handler.return_value = mock_stream_handler
        
        # Mock log files
        mock_log_dir = MagicMock()
        mock_log_file = MagicMock()
        mock_log_file.name = "app.log"
        mock_log_file.stat.return_value.st_size = 1024
        mock_log_file.stat.return_value.st_mtime = 1640995200.0
        mock_log_dir.glob.return_value = [mock_log_file]
        mock_log_dir.exists.return_value = True
        mock_path.return_value = mock_log_dir
        
        response = client.get("/v1/system/logs/stats", headers=admin_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_logs"] == 3
        assert "logs_by_level" in data
        assert data["logs_by_level"]["INFO"] == 1
        assert data["logs_by_level"]["ERROR"] == 1
        assert len(data["recent_errors"]) == 1
        assert len(data["log_files"]) == 1

class TestDatabaseStats:
    """Test database statistics endpoints."""
    
    def test_get_database_stats_success(self, client: TestClient, admin_headers: dict, session: Session):
        """Test successful database statistics retrieval."""
        # Create test data
        users = [
            User(username=f"user{i}", email=f"user{i}@test.com", hashed_password="hash")
            for i in range(5)
        ]
        session.add_all(users)
        session.commit()
        
        response = client.get("/v1/system/database/stats", headers=admin_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_users"] == 5
        assert "recent_activity" in data

class TestHealthCheck:
    """Test health check endpoints."""
    
    @patch('app.routers.system.psutil')
    @patch('app.routers.system.logging_manager')
    def test_health_check_healthy(self, mock_logging_manager, mock_psutil, client: TestClient):
        """Test health check when system is healthy."""
        # Mock system metrics
        mock_psutil.cpu_percent.return_value = 50.0
        mock_memory = MagicMock()
        mock_memory.percent = 60.0
        mock_psutil.virtual_memory.return_value = mock_memory
        mock_disk = MagicMock()
        mock_disk.used = 500 * 1024**3
        mock_disk.total = 1024**4
        mock_psutil.disk_usage.return_value = mock_disk
        mock_psutil.boot_time.return_value = 1640995200.0
        
        # Mock logging manager
        mock_logging_manager.__bool__ = lambda x: True
        
        response = client.get("/v1/system/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "checks" in data
        assert "system" in data["checks"]
        assert data["checks"]["system"]["status"] == "healthy"
    
    @patch('app.routers.system.psutil')
    def test_health_check_degraded(self, mock_psutil, client: TestClient):
        """Test health check when system is degraded."""
        # Mock high resource usage
        mock_psutil.cpu_percent.return_value = 95.0  # High CPU
        mock_memory = MagicMock()
        mock_memory.percent = 95.0  # High memory
        mock_psutil.virtual_memory.return_value = mock_memory
        mock_disk = MagicMock()
        mock_disk.used = 950 * 1024**3
        mock_disk.total = 1024**4  # High disk usage
        mock_psutil.disk_usage.return_value = mock_disk
        mock_psutil.boot_time.return_value = 1640995200.0
        
        response = client.get("/v1/system/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["degraded", "unhealthy"]
        assert len(data["warnings"]) > 0

class TestSystemRestart:
    """Test system restart functionality."""
    
    def test_restart_system_admin(self, client: TestClient, admin_headers: dict):
        """Test system restart with admin privileges."""
        response = client.post("/v1/system/restart", headers=admin_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "restart initiated" in data["message"]
        assert data["status"] == "success"
    
    def test_restart_system_unauthorized(self, client: TestClient, user_headers: dict):
        """Test system restart without admin privileges."""
        response = client.post("/v1/system/restart", headers=user_headers)
        assert response.status_code == 403

class TestSystemConfig:
    """Test system configuration endpoints."""
    
    @patch('app.routers.system.settings')
    def test_get_system_config(self, mock_settings, client: TestClient, admin_headers: dict):
        """Test system configuration retrieval."""
        # Mock settings
        mock_settings.API_VERSION = "1.0.0"
        mock_settings.DEBUG = False
        mock_settings.HOST = "0.0.0.0"
        mock_settings.PORT = 8000
        mock_settings.LOG_LEVEL = "INFO"
        mock_settings.DATABASE_URL = "postgresql://..."
        mock_settings.SSL_CERTFILE = None
        mock_settings.SSL_KEYFILE = None
        mock_settings.RATE_LIMIT_REQUESTS = 100
        mock_settings.RATE_LIMIT_WINDOW = 60
        mock_settings.LOG_TO_CONSOLE = True
        mock_settings.LOG_TO_FILE = True
        mock_settings.LOG_JSON_FORMAT = False
        mock_settings.LOG_STREAM_ENABLED = True
        mock_settings.SELFTEST_ENABLED = True
        mock_settings.SELFTEST_INTERVAL_MINUTES = 5
        mock_settings.MONITORING_ENABLED = True
        mock_settings.LOG_PERFORMANCE_TRACKING = True
        
        response = client.get("/v1/system/config", headers=admin_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["api_version"] == "1.0.0"
        assert data["debug_mode"] == False
        assert data["host"] == "0.0.0.0"
        assert data["port"] == 8000
        assert "rate_limiting" in data
        assert "logging" in data
        assert "self_tests" in data
        assert "monitoring" in data

if __name__ == "__main__":
    pytest.main([__file__])
