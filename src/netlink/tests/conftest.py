"""
NetLink Consolidated Test Configuration and Fixtures

Pytest configuration and shared fixtures for all NetLink tests.
Combines fixtures from both root tests/ and src/netlink/tests/ directories.
"""

import pytest
import asyncio
import tempfile
import shutil
import json
import time
from pathlib import Path
from typing import Dict, Any, Generator, Optional
from unittest.mock import Mock, AsyncMock
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Configure pytest
pytest_plugins = ["pytest_asyncio"]

# Test markers
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "slow: Tests that take a long time")
    config.addinivalue_line("markers", "auth: Authentication tests")
    config.addinivalue_line("markers", "backup: Backup system tests")
    config.addinivalue_line("markers", "database: Database tests")
    config.addinivalue_line("markers", "api: API tests")
    config.addinivalue_line("markers", "gui: GUI tests")
    config.addinivalue_line("markers", "cli: CLI tests")


# Core Configuration Fixtures
@pytest.fixture(scope="session")
def test_config() -> Dict[str, Any]:
    """Comprehensive test configuration fixture."""
    return {
        "database": {
            "type": "sqlite",
            "path": ":memory:",
            "echo": False,
            "pool_size": 5,
            "max_overflow": 10
        },
        "server": {
            "host": "127.0.0.1",
            "port": 8888,
            "debug": True,
            "testing": True
        },
        "auth": {
            "secret_key": "test_secret_key_netlink_12345",
            "algorithm": "HS256",
            "access_token_expire_minutes": 30,
            "refresh_token_expire_days": 7,
            "password_min_length": 8
        },
        "backup": {
            "test_directory": "/tmp/netlink_test_backups",
            "encryption_key": "test_encryption_key_government_level_12345",
            "shard_size_mb": 5,  # Smaller for testing
            "redundancy_level": 2,
            "compression_enabled": True
        },
        "security": {
            "encryption_level": "GOVERNMENT",
            "quantum_resistant": True,
            "zero_knowledge": True,
            "multi_key_architecture": True
        },
        "performance": {
            "max_response_time": 2.0,
            "max_memory_usage_mb": 100,
            "concurrent_users": 100
        },
        "ai": {
            "provider": "mock",
            "model": "test-model",
            "api_key": "test_api_key",
            "max_tokens": 1000
        }
    }


# Directory and File Fixtures
@pytest.fixture(scope="function")
def temp_directory() -> Generator[Path, None, None]:
    """Create temporary directory for tests."""
    temp_dir = Path(tempfile.mkdtemp(prefix="netlink_test_"))
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(scope="function")
def temp_file() -> Generator[Path, None, None]:
    """Create temporary file for tests."""
    temp_file = Path(tempfile.mktemp(prefix="netlink_test_", suffix=".tmp"))
    yield temp_file
    if temp_file.exists():
        temp_file.unlink()


# Database Fixtures
@pytest.fixture(scope="function")
async def test_db(test_config):
    """Test database fixture with in-memory SQLite."""
    try:
        from src.netlink.core.database import DatabaseManager
        
        db_manager = DatabaseManager(test_config["database"])
        await db_manager.initialize()
        
        # Create test tables
        await db_manager.create_test_schema()
        
        yield db_manager
        
        await db_manager.close()
    except ImportError:
        # Mock database if not available
        mock_db = Mock()
        mock_db.execute = AsyncMock()
        mock_db.fetch_all = AsyncMock(return_value=[])
        mock_db.fetch_one = AsyncMock(return_value=None)
        yield mock_db


# User and Authentication Fixtures
@pytest.fixture(scope="session")
def test_user() -> Dict[str, Any]:
    """Test user data fixture."""
    return {
        "id": 1,
        "username": "testuser",
        "email": "testuser@example.com",
        "password": "testpassword123",
        "first_name": "Test",
        "last_name": "User",
        "is_active": True,
        "is_admin": False,
        "created_at": "2024-01-01T00:00:00Z",
        "permissions": ["read", "write"]
    }


@pytest.fixture(scope="session")
def admin_user() -> Dict[str, Any]:
    """Admin user data fixture."""
    return {
        "id": 2,
        "username": "admin",
        "email": "admin@example.com",
        "password": "adminpassword123",
        "first_name": "Admin",
        "last_name": "User",
        "is_active": True,
        "is_admin": True,
        "created_at": "2024-01-01T00:00:00Z",
        "permissions": ["read", "write", "admin", "backup", "security"]
    }


@pytest.fixture(scope="function")
async def test_token(test_user, test_config):
    """Generate test JWT token."""
    try:
        from src.netlink.core.auth import TokenManager
        
        token_manager = TokenManager(test_config["auth"])
        token = await token_manager.create_access_token(
            user_id=test_user["id"],
            username=test_user["username"]
        )
        return token
    except ImportError:
        return "test_token_12345"


@pytest.fixture(scope="function")
async def admin_token(admin_user, test_config):
    """Generate admin JWT token."""
    try:
        from src.netlink.core.auth import TokenManager
        
        token_manager = TokenManager(test_config["auth"])
        token = await token_manager.create_access_token(
            user_id=admin_user["id"],
            username=admin_user["username"],
            is_admin=True
        )
        return token
    except ImportError:
        return "admin_token_12345"


# HTTP Client Fixtures
@pytest.fixture(scope="function")
async def http_client(test_config):
    """HTTP client for API testing."""
    try:
        import httpx
        
        async with httpx.AsyncClient(
            base_url=f"http://{test_config['server']['host']}:{test_config['server']['port']}",
            timeout=30.0
        ) as client:
            yield client
    except ImportError:
        # Mock HTTP client if httpx not available
        mock_client = Mock()
        mock_client.get = AsyncMock()
        mock_client.post = AsyncMock()
        mock_client.put = AsyncMock()
        mock_client.delete = AsyncMock()
        yield mock_client


# Mock Service Fixtures
@pytest.fixture(scope="function")
def mock_auth_service():
    """Mock authentication service."""
    mock = Mock()
    mock.authenticate = AsyncMock(return_value={"success": True, "user_id": 1})
    mock.create_user = AsyncMock(return_value={"id": 1, "username": "testuser"})
    mock.validate_token = AsyncMock(return_value=True)
    mock.refresh_token = AsyncMock(return_value="new_token")
    return mock


@pytest.fixture(scope="function")
def mock_backup_service():
    """Mock backup service."""
    mock = Mock()
    mock.create_backup = AsyncMock(return_value="backup_123")
    mock.restore_backup = AsyncMock(return_value={"data": "restored"})
    mock.list_backups = AsyncMock(return_value=[])
    mock.delete_backup = AsyncMock(return_value=True)
    return mock


@pytest.fixture(scope="function")
def mock_database_service():
    """Mock database service."""
    mock = Mock()
    mock.execute = AsyncMock()
    mock.fetch_all = AsyncMock(return_value=[])
    mock.fetch_one = AsyncMock(return_value=None)
    mock.insert = AsyncMock(return_value=1)
    mock.update = AsyncMock(return_value=True)
    mock.delete = AsyncMock(return_value=True)
    return mock


# Performance Monitoring Fixtures
@pytest.fixture(scope="function")
def performance_monitor():
    """Performance monitoring fixture."""
    class PerformanceMonitor:
        def __init__(self):
            self.start_time = None
            self.start_memory = None
            self.metrics = {}
        
        def start(self):
            self.start_time = time.time()
            # Mock memory usage
            self.start_memory = 50 * 1024 * 1024  # 50MB
        
        def stop(self):
            if self.start_time is None:
                return {"error": "Monitor not started"}
            
            duration = time.time() - self.start_time
            # Mock memory delta
            memory_delta = 10 * 1024 * 1024  # 10MB increase
            
            self.metrics = {
                "duration": duration,
                "memory_delta": memory_delta,
                "start_memory": self.start_memory,
                "end_memory": self.start_memory + memory_delta
            }
            return self.metrics
    
    return PerformanceMonitor()


# Security Testing Fixtures
@pytest.fixture(scope="function")
def security_scanner():
    """Security scanner fixture for testing vulnerabilities."""
    class SecurityScanner:
        def __init__(self):
            self.vulnerabilities = []
        
        async def scan_sql_injection(self, input_data):
            """Mock SQL injection scanning."""
            sql_patterns = ["'", "--", "DROP", "DELETE", "INSERT", "UPDATE"]
            for pattern in sql_patterns:
                if pattern.lower() in str(input_data).lower():
                    self.vulnerabilities.append(f"Potential SQL injection: {pattern}")
            return len(self.vulnerabilities) == 0
        
        async def scan_xss(self, input_data):
            """Mock XSS scanning."""
            xss_patterns = ["<script>", "javascript:", "onload=", "onerror="]
            for pattern in xss_patterns:
                if pattern.lower() in str(input_data).lower():
                    self.vulnerabilities.append(f"Potential XSS: {pattern}")
            return len(self.vulnerabilities) == 0
        
        async def scan_file_upload(self, file_path):
            """Mock file upload security scanning."""
            dangerous_extensions = [".exe", ".bat", ".sh", ".php", ".jsp"]
            file_ext = Path(file_path).suffix.lower()
            if file_ext in dangerous_extensions:
                self.vulnerabilities.append(f"Dangerous file extension: {file_ext}")
            return len(self.vulnerabilities) == 0
        
        def get_vulnerabilities(self):
            return self.vulnerabilities.copy()
    
    return SecurityScanner()


# Sample Data Fixtures
@pytest.fixture(scope="session")
def sample_message_data():
    """Sample message data for testing."""
    return {
        "id": 1,
        "user_id": 1,
        "content": "Hello, this is a test message!",
        "timestamp": "2024-01-01T12:00:00Z",
        "channel_id": 1,
        "message_type": "text",
        "attachments": [],
        "reactions": [],
        "edited": False
    }


@pytest.fixture(scope="session")
def sample_file_data():
    """Sample file data for testing."""
    return {
        "id": 1,
        "filename": "test_document.txt",
        "content_type": "text/plain",
        "size": 1024,
        "uploaded_by": 1,
        "uploaded_at": "2024-01-01T12:00:00Z",
        "checksum": "abc123def456",
        "virus_scanned": True,
        "scan_result": "clean"
    }


# Async Event Loop Fixture
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Cleanup Fixtures
@pytest.fixture(autouse=True)
async def cleanup_after_test():
    """Automatic cleanup after each test."""
    yield
    # Cleanup code here if needed
    await asyncio.sleep(0.01)  # Allow pending tasks to complete
