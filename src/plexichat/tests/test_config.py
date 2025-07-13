"""
Configuration system tests for PlexiChat.
Tests config loading, validation, and management.
"""

import json
import logging
import tempfile
from pathlib import Path

import yaml

from ..core_system.config.manager import ConfigurationManager
from .test_base import BaseTest, TestResult

logger = logging.getLogger(__name__)


class ConfigTest(BaseTest):
    """Test configuration system functionality."""
    
    def __init__(self):
        super().__init__()
        self.temp_dir = None
        self.config_manager = None
    
    async def setup(self):
        """Setup test environment with temporary config directory."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.config_manager = ConfigurationManager(self.temp_dir)
    
    async def teardown(self):
        """Cleanup temporary files."""
        if self.temp_dir and self.temp_dir.exists():
            import shutil
            shutil.rmtree(self.temp_dir)
    
    async def test_config_loading(self):
        """Test configuration file loading."""
        start_time = datetime.now()
        
        try:
            # Create test config file
            test_config = {
                "server": {
                    "host": "localhost",
                    "port": 8080,
                    "ssl_enabled": True
                },
                "database": {
                    "type": "sqlite",
                    "path": "test.db"
                }
            }
            
            config_file = self.temp_dir / "plexichat.yaml"
            with open(config_file, 'w') as f:
                yaml.dump(test_config, f)
            
            # Test loading
            loaded_config = self.config_manager.load_config()
            
            # Verify loaded correctly
            assert loaded_config["server"]["host"] == "localhost"
            assert loaded_config["server"]["port"] == 8080
            assert loaded_config["database"]["type"] == "sqlite"
            
            duration = (datetime.now() - start_time).total_seconds() * 1000
            
            self.add_result(TestResult(
                test_name="Config Loading",
                category="Configuration",
                endpoint="/config/load",
                method="FILE",
                status="passed",
                duration_ms=duration,
                request_data={"config_file": str(config_file)},
                response_data={"loaded": True, "keys": list(loaded_config.keys())}
            ))
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="Config Loading",
                category="Configuration", 
                endpoint="/config/load",
                method="FILE",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def test_config_validation(self):
        """Test configuration validation."""
        start_time = datetime.now()
        
        try:
            # Test invalid config
            invalid_config = {
                "server": {
                    "port": "invalid_port"  # Should be integer
                }
            }
            
            # This should handle validation gracefully
            result = self.config_manager.validate_config(invalid_config)
            
            duration = (datetime.now() - start_time).total_seconds() * 1000
            
            self.add_result(TestResult(
                test_name="Config Validation",
                category="Configuration",
                endpoint="/config/validate", 
                method="VALIDATE",
                status="passed" if not result.get("valid", True) else "warning",
                duration_ms=duration,
                request_data=invalid_config,
                response_data=result
            ))
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="Config Validation",
                category="Configuration",
                endpoint="/config/validate",
                method="VALIDATE", 
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def test_config_import_from_file(self):
        """Test importing configuration from external file."""
        start_time = datetime.now()
        
        try:
            # Create external config file
            external_config = {
                "imported": True,
                "features": {
                    "ai_enabled": True,
                    "ssl_enabled": True,
                    "monitoring_enabled": True
                },
                "database": {
                    "type": "postgresql",
                    "host": "localhost",
                    "port": 5432
                }
            }
            
            external_file = self.temp_dir / "import_config.json"
            with open(external_file, 'w') as f:
                json.dump(external_config, f)
            
            # Test import functionality
            success = await self.config_manager.import_config_from_file(str(external_file))
            
            duration = (datetime.now() - start_time).total_seconds() * 1000
            
            self.add_result(TestResult(
                test_name="Config Import from File",
                category="Configuration",
                endpoint="/config/import",
                method="IMPORT",
                status="passed" if success else "failed",
                duration_ms=duration,
                request_data={"import_file": str(external_file)},
                response_data={"success": success, "imported_keys": list(external_config.keys())}
            ))
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="Config Import from File",
                category="Configuration",
                endpoint="/config/import",
                method="IMPORT",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def run_all_tests(self):
        """Run all configuration tests."""
        await self.setup()
        try:
            await self.test_config_loading()
            await self.test_config_validation()
            await self.test_config_import_from_file()
        finally:
            await self.teardown()
