#!/usr/bin/env python3
"""
Test suite for PlexiChat Database Setup System
Comprehensive tests for database setup wizard and external database support.
"""

import os
import sys
import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.plexichat.core.database_setup_wizard import (
    DatabaseSetupWizard, DatabaseType, SetupStep, DatabaseConnection
)
from src.plexichat.core.external_database import (
    ExternalDatabaseManager, DatabaseProvider, DatabaseEngine, ExternalDatabaseConfig
)

class TestDatabaseSetupWizard:
    """Test cases for database setup wizard."""
    
    def setup_method(self):
        """Set up test environment."""
        self.wizard = DatabaseSetupWizard()
        self.temp_dir = tempfile.mkdtemp()
        self.wizard.config_dir = Path(self.temp_dir)
    
    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_wizard_initialization(self):
        """Test wizard initialization."""
        assert self.wizard.progress.current_step == SetupStep.WELCOME
        assert len(self.wizard.progress.completed_steps) == 0
        assert self.wizard.progress.connection_config is None
    
    def test_get_database_types(self):
        """Test getting available database types."""
        types = self.wizard.get_database_types()
        
        assert "database_types" in types
        assert len(types["database_types"]) == 4
        
        # Check that all expected types are present
        type_values = [db["type"] for db in types["database_types"]]
        assert "sqlite" in type_values
        assert "postgresql" in type_values
        assert "mysql" in type_values
        assert "mariadb" in type_values
    
    def test_set_database_type_sqlite(self):
        """Test setting SQLite database type."""
        result = self.wizard.set_database_type("sqlite")
        
        assert result["success"] is True
        assert self.wizard.progress.connection_config is not None
        assert self.wizard.progress.connection_config.db_type == DatabaseType.SQLITE
        assert SetupStep.DATABASE_TYPE in self.wizard.progress.completed_steps
        assert self.wizard.progress.current_step == SetupStep.CONNECTION_DETAILS
    
    def test_set_database_type_postgresql(self):
        """Test setting PostgreSQL database type."""
        result = self.wizard.set_database_type("postgresql")
        
        assert result["success"] is True
        assert self.wizard.progress.connection_config.db_type == DatabaseType.POSTGRESQL
        assert self.wizard.progress.connection_config.port == 5432
    
    def test_set_invalid_database_type(self):
        """Test setting invalid database type."""
        result = self.wizard.set_database_type("invalid_db")
        
        assert result["success"] is False
        assert "error" in result
        assert "Invalid database type" in result["error"]
    
    def test_set_connection_details_sqlite(self):
        """Test setting SQLite connection details."""
        # First set database type
        self.wizard.set_database_type("sqlite")
        
        details = {"file_path": "test_database.db"}
        result = self.wizard.set_connection_details(details)
        
        assert result["success"] is True
        assert self.wizard.progress.connection_config.file_path == "test_database.db"
        assert SetupStep.CONNECTION_DETAILS in self.wizard.progress.completed_steps
    
    def test_set_connection_details_postgresql(self):
        """Test setting PostgreSQL connection details."""
        # First set database type
        self.wizard.set_database_type("postgresql")
        
        details = {
            "host": "localhost",
            "port": 5432,
            "database": "test_db"
        }
        result = self.wizard.set_connection_details(details)
        
        assert result["success"] is True
        assert self.wizard.progress.connection_config.host == "localhost"
        assert self.wizard.progress.connection_config.port == 5432
        assert self.wizard.progress.connection_config.database == "test_db"
    
    def test_set_authentication(self):
        """Test setting authentication details."""
        # Set up PostgreSQL database type and connection
        self.wizard.set_database_type("postgresql")
        self.wizard.set_connection_details({"host": "localhost", "port": 5432})
        
        auth_details = {
            "username": "test_user",
            "password": "test_password"
        }
        result = self.wizard.set_authentication(auth_details)
        
        assert result["success"] is True
        assert self.wizard.progress.connection_config.username == "test_user"
        assert self.wizard.progress.connection_config.password == "test_password"
        assert SetupStep.AUTHENTICATION in self.wizard.progress.completed_steps
    
    def test_set_advanced_settings(self):
        """Test setting advanced settings."""
        # Set up database
        self.wizard.set_database_type("postgresql")
        self.wizard.set_connection_details({"host": "localhost"})
        
        settings = {
            "pool_size": 20,
            "max_overflow": 30,
            "ssl_mode": "require"
        }
        result = self.wizard.set_advanced_settings(settings)
        
        assert result["success"] is True
        assert self.wizard.progress.connection_config.pool_size == 20
        assert self.wizard.progress.connection_config.max_overflow == 30
        assert self.wizard.progress.connection_config.ssl_mode == "require"
    
    def test_get_wizard_status(self):
        """Test getting wizard status."""
        status = self.wizard.get_wizard_status()
        
        assert "current_step" in status
        assert "completed_steps" in status
        assert "progress_percentage" in status
        assert "has_errors" in status
        assert "connection_configured" in status
        
        # Initially no steps completed
        assert status["progress_percentage"] == 0
        assert status["connection_configured"] is False
    
    def test_reset_wizard(self):
        """Test resetting the wizard."""
        # Set up some progress
        self.wizard.set_database_type("sqlite")
        self.wizard.set_connection_details({"file_path": "test.db"})
        
        # Verify progress exists
        assert len(self.wizard.progress.completed_steps) > 0
        assert self.wizard.progress.connection_config is not None
        
        # Reset wizard
        result = self.wizard.reset_wizard()
        
        assert result["success"] is True
        assert len(self.wizard.progress.completed_steps) == 0
        assert self.wizard.progress.connection_config is None
        assert self.wizard.progress.current_step == SetupStep.WELCOME

class TestExternalDatabaseManager:
    """Test cases for external database manager."""
    
    def setup_method(self):
        """Set up test environment."""
        self.manager = ExternalDatabaseManager()
    
    def test_manager_initialization(self):
        """Test manager initialization."""
        assert self.manager.config is None
        assert self.manager.engine is None
        assert self.manager.is_connected is False
    
    def test_get_supported_providers(self):
        """Test getting supported providers."""
        providers = self.manager.get_supported_providers()
        
        assert len(providers) > 0
        
        # Check for key providers
        provider_names = [p["provider"] for p in providers]
        assert "aws_rds" in provider_names
        assert "supabase" in provider_names
        assert "google_cloud_sql" in provider_names
    
    def test_get_provider_info(self):
        """Test getting provider information."""
        info = self.manager.get_provider_info(DatabaseProvider.AWS_RDS)
        
        assert "name" in info
        assert "supported_engines" in info
        assert "ssl_required" in info
        assert info["name"] == "Amazon RDS"
    
    def test_validate_config_valid(self):
        """Test validating valid configuration."""
        config = ExternalDatabaseConfig(
            provider=DatabaseProvider.AWS_RDS,
            engine=DatabaseEngine.POSTGRESQL,
            host="test.amazonaws.com",
            port=5432,
            database="testdb",
            username="testuser",
            password="testpass"
        )
        
        result = self.manager._validate_config(config)
        
        assert result["valid"] is True
        assert len(result["errors"]) == 0
    
    def test_validate_config_invalid(self):
        """Test validating invalid configuration."""
        config = ExternalDatabaseConfig(
            provider=DatabaseProvider.AWS_RDS,
            engine=DatabaseEngine.POSTGRESQL,
            host="",  # Invalid: empty host
            port=0,   # Invalid: invalid port
            database="testdb",
            username="",  # Invalid: empty username
            password=""   # Invalid: empty password
        )
        
        result = self.manager._validate_config(config)
        
        assert result["valid"] is False
        assert len(result["errors"]) > 0
        assert any("Host is required" in error for error in result["errors"])
        assert any("Username is required" in error for error in result["errors"])
    
    def test_connection_string_postgresql(self):
        """Test PostgreSQL connection string generation."""
        config = ExternalDatabaseConfig(
            provider=DatabaseProvider.AWS_RDS,
            engine=DatabaseEngine.POSTGRESQL,
            host="test.amazonaws.com",
            port=5432,
            database="testdb",
            username="testuser",
            password="testpass",
            ssl_enabled=True,
            ssl_mode="require"
        )
        
        conn_str = config.get_connection_string()
        
        assert conn_str.startswith("postgresql://")
        assert "testuser:testpass" in conn_str
        assert "test.amazonaws.com:5432" in conn_str
        assert "testdb" in conn_str
        assert "sslmode=require" in conn_str
    
    def test_connection_string_mysql(self):
        """Test MySQL connection string generation."""
        config = ExternalDatabaseConfig(
            provider=DatabaseProvider.PLANETSCALE,
            engine=DatabaseEngine.MYSQL,
            host="test.planetscale.com",
            port=3306,
            database="testdb",
            username="testuser",
            password="testpass",
            ssl_enabled=True
        )
        
        conn_str = config.get_connection_string()
        
        assert conn_str.startswith("mysql+pymysql://")
        assert "testuser:testpass" in conn_str
        assert "test.planetscale.com:3306" in conn_str
        assert "testdb" in conn_str
        assert "ssl_disabled=false" in conn_str
    
    def test_get_provider_setup_guide(self):
        """Test getting provider setup guide."""
        guide = self.manager.get_provider_setup_guide(DatabaseProvider.SUPABASE)
        
        assert "steps" in guide
        assert "connection_format" in guide
        assert "documentation" in guide
        assert len(guide["steps"]) > 0

class TestDatabaseConnection:
    """Test cases for database connection configuration."""
    
    def test_sqlite_connection_string(self):
        """Test SQLite connection string generation."""
        conn = DatabaseConnection(
            db_type=DatabaseType.SQLITE,
            file_path="test.db"
        )
        
        conn_str = conn.get_connection_string()
        assert conn_str == "sqlite:///test.db"
    
    def test_postgresql_connection_string(self):
        """Test PostgreSQL connection string generation."""
        conn = DatabaseConnection(
            db_type=DatabaseType.POSTGRESQL,
            host="localhost",
            port=5432,
            database="testdb",
            username="user",
            password="pass"
        )
        
        conn_str = conn.get_connection_string()
        expected = "postgresql://user:pass@localhost:5432/testdb"
        assert conn_str == expected
    
    def test_mysql_connection_string(self):
        """Test MySQL connection string generation."""
        conn = DatabaseConnection(
            db_type=DatabaseType.MYSQL,
            host="localhost",
            port=3306,
            database="testdb",
            username="user",
            password="pass",
            charset="utf8mb4"
        )
        
        conn_str = conn.get_connection_string()
        assert conn_str.startswith("mysql+pymysql://user:pass@localhost:3306/testdb")
        assert "charset=utf8mb4" in conn_str

# Integration tests (require actual database connections)
class TestDatabaseIntegration:
    """Integration tests for database setup (requires actual databases)."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_sqlite_setup_integration(self):
        """Test complete SQLite setup process."""
        wizard = DatabaseSetupWizard()
        temp_dir = tempfile.mkdtemp()
        wizard.config_dir = Path(temp_dir)
        
        try:
            # Complete setup process
            wizard.set_database_type("sqlite")
            wizard.set_connection_details({"file_path": f"{temp_dir}/test.db"})
            wizard.set_advanced_settings({})
            
            # Test connection
            result = await wizard.test_connection()
            assert result["success"] is True
            
            # Initialize schema
            result = await wizard.initialize_schema()
            assert result["success"] is True
            
            # Save configuration
            result = wizard.save_configuration()
            assert result["success"] is True
            
            # Verify files were created
            assert (Path(temp_dir) / "database.yaml").exists()
            assert (Path(temp_dir) / "database.json").exists()
            
        finally:
            shutil.rmtree(temp_dir)

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
