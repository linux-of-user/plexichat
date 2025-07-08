"""Configuration system tests."""
import pytest
from src.netlink.core.config import config_manager, NetLinkConfig

@pytest.mark.unit
class TestConfigSystem:
    """Test configuration system functionality."""
    
    def test_config_manager_initialization(self):
        """Test config manager initializes correctly."""
        assert config_manager is not None
        assert hasattr(config_manager, 'config')
    
    def test_config_loading(self):
        """Test configuration loading."""
        config = config_manager.config
        assert isinstance(config, NetLinkConfig)
        assert config.app_name == "NetLink"
    
    def test_config_validation(self):
        """Test configuration validation."""
        errors = config_manager.validate_config()
        assert isinstance(errors, list)
        # Should have no errors with default config
        assert len(errors) == 0
    
    def test_config_value_access(self):
        """Test configuration value access."""
        app_name = config_manager.get_config_value("app_name")
        assert app_name == "NetLink"
        
        # Test nested value access
        server_host = config_manager.get_config_value("server.host")
        assert server_host == "0.0.0.0"
        
        # Test default value
        nonexistent = config_manager.get_config_value("nonexistent.key", "default")
        assert nonexistent == "default"
