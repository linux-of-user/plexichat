"""
NetLink Test Configuration

Pytest configuration and fixtures for the unified testing framework.
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Generator
import logging

# Configure test logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    temp_path = Path(tempfile.mkdtemp(prefix="netlink_test_"))
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def test_config() -> Dict[str, Any]:
    """Test configuration."""
    return {
        "database_url": "sqlite:///./test_netlink.db",
        "test_mode": True,
        "debug": True,
        "security": {
            "secret_key": "test-secret-key",
            "jwt_expiration_minutes": 5
        },
        "backup": {
            "enabled": False,
            "storage_path": "test_data/backups"
        },
        "clustering": {
            "enabled": False
        },
        "ai": {
            "enabled": False
        }
    }


@pytest.fixture
async def test_database():
    """Setup test database."""
    # Database setup logic would go here
    logger.info("📊 Test database setup")
    yield "test_db"
    logger.info("🧹 Test database cleanup")


@pytest.fixture
def mock_services():
    """Mock external services for testing."""
    class MockServices:
        def __init__(self):
            self.ai_service = None
            self.backup_service = None
            self.security_service = None
        
        def setup_mocks(self):
            # Mock setup logic would go here
            pass
        
        def teardown_mocks(self):
            # Mock teardown logic would go here
            pass
    
    services = MockServices()
    services.setup_mocks()
    yield services
    services.teardown_mocks()


# Test markers
pytest.mark.unit = pytest.mark.unit
pytest.mark.integration = pytest.mark.integration
pytest.mark.e2e = pytest.mark.e2e
pytest.mark.slow = pytest.mark.slow
pytest.mark.security = pytest.mark.security
pytest.mark.performance = pytest.mark.performance
