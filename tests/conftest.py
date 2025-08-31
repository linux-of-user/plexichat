"""
Pytest configuration and fixtures for authentication system tests.
"""

import pytest
import tempfile
import json
from unittest.mock import MagicMock, AsyncMock, patch
from pathlib import Path

from plexichat.core.authentication import UnifiedAuthManager
from plexichat.core.auth.config.auth_config import AuthConfig
from plexichat.core.auth.services.authentication_service import AuthenticationService
from plexichat.core.auth.services.service_container import AuthServiceContainer


@pytest.fixture
def mock_security_system():
    """Create mock security system for testing."""
    mock_system = MagicMock()
    mock_system.user_credentials = {}
    mock_system.token_manager = MagicMock()
    mock_system.password_manager = MagicMock()
    mock_system.authenticate_user = AsyncMock(return_value=(True, MagicMock(
        user_id="testuser",
        permissions={"read"}
    )))
    mock_system.token_manager.create_access_token = MagicMock(return_value="access_token_123")
    mock_system.token_manager.create_refresh_token = MagicMock(return_value="refresh_token_456")
    mock_system.token_manager.verify_token = MagicMock(return_value=(True, {
        'user_id': 'testuser',
        'permissions': ['read', 'write'],
        'token_type': 'access'
    }))
    return mock_system


@pytest.fixture
def auth_manager(mock_security_system):
    """Create authentication manager with mocked dependencies."""
    with patch('plexichat.core.authentication.get_security_system', return_value=mock_security_system):
        manager = UnifiedAuthManager(mock_security_system)
        return manager


@pytest.fixture
def auth_service(mock_security_system):
    """Create authentication service with mocked dependencies."""
    with patch('plexichat.core.auth.services.authentication_service.get_security_system', return_value=mock_security_system):
        service = AuthenticationService()
        return service


@pytest.fixture
def service_container():
    """Create service container for dependency injection testing."""
    container = AuthServiceContainer()
    return container


@pytest.fixture
def temp_config_file(tmp_path):
    """Create a temporary configuration file for testing."""
    config_data = {
        "auth": {
            "session_timeout_minutes": 30,
            "max_failed_attempts": 3,
            "enable_mfa": True,
            "enable_device_tracking": True,
            "password_policy": {
                "min_length": 8,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_numbers": True,
                "require_special_chars": False,
                "complexity_score_threshold": 50
            },
            "security": {
                "brute_force_protection": True,
                "max_concurrent_sessions": 5,
                "session_cleanup_interval": 300,
                "risk_assessment_enabled": True
            }
        }
    }

    config_file = tmp_path / "test_config.json"
    with open(config_file, 'w') as f:
        json.dump(config_data, f, indent=2)

    return str(config_file)


@pytest.fixture
def performance_auth_service(mock_security_system):
    """Create auth service optimized for performance testing."""
    with patch('plexichat.core.auth.services.authentication_service.get_security_system', return_value=mock_security_system):
        service = AuthenticationService()
        return service