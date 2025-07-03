"""
NetLink External Database Support
Comprehensive external database hosting and management system.
"""

import os
import json
import yaml
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
import sqlalchemy
from sqlalchemy import create_engine, text, MetaData, Table
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool, NullPool
import psycopg2
import pymysql
import sqlite3
import secrets
import base64

logger = logging.getLogger(__name__)

# Import encryption manager (will be available after creation)
try:
    from netlink.app.security.database_encryption import EncryptedDatabaseManager
except ImportError:
    logger.warning("Database encryption not available - running without encryption")

class DatabaseProvider(str, Enum):
    """External database providers."""
    AWS_RDS = "aws_rds"
    GOOGLE_CLOUD_SQL = "google_cloud_sql"
    AZURE_DATABASE = "azure_database"
    DIGITAL_OCEAN = "digital_ocean"
    HEROKU_POSTGRES = "heroku_postgres"
    PLANETSCALE = "planetscale"
    SUPABASE = "supabase"
    RAILWAY = "railway"
    RENDER = "render"
    SELF_HOSTED = "self_hosted"

class DatabaseEngine(str, Enum):
    """Database engines."""
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MARIADB = "mariadb"
    SQLITE = "sqlite"

@dataclass
class ExternalDatabaseConfig:
    """External database configuration."""
    provider: DatabaseProvider
    engine: DatabaseEngine
    host: str
    port: int
    database: str
    username: str
    password: str
    
    # SSL/TLS Configuration
    ssl_enabled: bool = True
    ssl_mode: str = "require"
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    ssl_ca_path: Optional[str] = None
    
    # Connection Pool Settings
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    pool_pre_ping: bool = True
    
    # Provider-specific settings
    region: Optional[str] = None
    instance_id: Optional[str] = None
    project_id: Optional[str] = None
    cluster_name: Optional[str] = None
    
    # Connection options
    connect_timeout: int = 30
    read_timeout: int = 30
    write_timeout: int = 30
    charset: str = "utf8mb4"
    
    # Monitoring and health
    health_check_interval: int = 300  # 5 minutes
    max_retries: int = 3
    retry_delay: int = 5
    
    def get_connection_string(self) -> str:
        """Generate connection string for external database."""
        if self.engine == DatabaseEngine.POSTGRESQL:
            base_url = f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
            params = []
            
            if self.ssl_enabled:
                params.append(f"sslmode={self.ssl_mode}")
                if self.ssl_cert_path:
                    params.append(f"sslcert={self.ssl_cert_path}")
                if self.ssl_key_path:
                    params.append(f"sslkey={self.ssl_key_path}")
                if self.ssl_ca_path:
                    params.append(f"sslrootcert={self.ssl_ca_path}")
            
            if self.connect_timeout:
                params.append(f"connect_timeout={self.connect_timeout}")
            
            if params:
                base_url += "?" + "&".join(params)
            return base_url
        
        elif self.engine in [DatabaseEngine.MYSQL, DatabaseEngine.MARIADB]:
            base_url = f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
            params = []
            
            if self.charset:
                params.append(f"charset={self.charset}")
            
            if self.ssl_enabled:
                params.append("ssl_disabled=false")
                if self.ssl_ca_path:
                    params.append(f"ssl_ca={self.ssl_ca_path}")
                if self.ssl_cert_path:
                    params.append(f"ssl_cert={self.ssl_cert_path}")
                if self.ssl_key_path:
                    params.append(f"ssl_key={self.ssl_key_path}")
            
            if params:
                base_url += "?" + "&".join(params)
            return base_url
        
        raise ValueError(f"Unsupported database engine: {self.engine}")

class ExternalDatabaseManager:
    """Manager for external database connections and operations."""
    
    def __init__(self, encryption_key: Optional[str] = None):
        self.config: Optional[ExternalDatabaseConfig] = None
        self.engine: Optional[Engine] = None
        self.is_connected = False
        self.last_health_check = None
        self.connection_pool_stats = {}

        # Initialize encryption manager
        try:
            self.encryption_manager = EncryptedDatabaseManager(encryption_key)
            self.encryption_enabled = True
            logger.info("External database encryption enabled")
        except NameError:
            self.encryption_manager = None
            self.encryption_enabled = False
            logger.warning("External database encryption not available")
        
        # Provider-specific configurations
        self.provider_configs = {
            DatabaseProvider.AWS_RDS: {
                "name": "Amazon RDS",
                "supported_engines": [DatabaseEngine.POSTGRESQL, DatabaseEngine.MYSQL],
                "default_ports": {DatabaseEngine.POSTGRESQL: 5432, DatabaseEngine.MYSQL: 3306},
                "ssl_required": True,
                "features": ["automated_backups", "read_replicas", "multi_az", "encryption"]
            },
            DatabaseProvider.GOOGLE_CLOUD_SQL: {
                "name": "Google Cloud SQL",
                "supported_engines": [DatabaseEngine.POSTGRESQL, DatabaseEngine.MYSQL],
                "default_ports": {DatabaseEngine.POSTGRESQL: 5432, DatabaseEngine.MYSQL: 3306},
                "ssl_required": True,
                "features": ["automated_backups", "read_replicas", "high_availability", "encryption"]
            },
            DatabaseProvider.AZURE_DATABASE: {
                "name": "Azure Database",
                "supported_engines": [DatabaseEngine.POSTGRESQL, DatabaseEngine.MYSQL],
                "default_ports": {DatabaseEngine.POSTGRESQL: 5432, DatabaseEngine.MYSQL: 3306},
                "ssl_required": True,
                "features": ["automated_backups", "read_replicas", "geo_redundancy", "encryption"]
            },
            DatabaseProvider.HEROKU_POSTGRES: {
                "name": "Heroku Postgres",
                "supported_engines": [DatabaseEngine.POSTGRESQL],
                "default_ports": {DatabaseEngine.POSTGRESQL: 5432},
                "ssl_required": True,
                "features": ["automated_backups", "continuous_protection", "dataclips"]
            },
            DatabaseProvider.SUPABASE: {
                "name": "Supabase",
                "supported_engines": [DatabaseEngine.POSTGRESQL],
                "default_ports": {DatabaseEngine.POSTGRESQL: 5432},
                "ssl_required": True,
                "features": ["realtime", "auth", "storage", "edge_functions"]
            },
            DatabaseProvider.PLANETSCALE: {
                "name": "PlanetScale",
                "supported_engines": [DatabaseEngine.MYSQL],
                "default_ports": {DatabaseEngine.MYSQL: 3306},
                "ssl_required": True,
                "features": ["branching", "schema_migrations", "insights", "serverless"]
            }
        }
    
    def get_provider_info(self, provider: DatabaseProvider) -> Dict[str, Any]:
        """Get information about a database provider."""
        return self.provider_configs.get(provider, {})
    
    def get_supported_providers(self) -> List[Dict[str, Any]]:
        """Get list of supported external database providers."""
        return [
            {
                "provider": provider.value,
                "config": config,
                "recommended": provider in [DatabaseProvider.AWS_RDS, DatabaseProvider.SUPABASE]
            }
            for provider, config in self.provider_configs.items()
        ]
    
    async def configure_external_database(self, config: ExternalDatabaseConfig) -> Dict[str, Any]:
        """Configure external database connection."""
        try:
            # Validate configuration
            validation_result = self._validate_config(config)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": "Configuration validation failed",
                    "validation_errors": validation_result["errors"]
                }
            
            self.config = config
            
            # Create engine with external database settings
            engine_kwargs = {
                "pool_size": config.pool_size,
                "max_overflow": config.max_overflow,
                "pool_timeout": config.pool_timeout,
                "pool_recycle": config.pool_recycle,
                "pool_pre_ping": config.pool_pre_ping,
                "echo": False  # Disable SQL echo for production
            }
            
            # Use QueuePool for external databases
            engine_kwargs["poolclass"] = QueuePool
            
            self.engine = create_engine(
                config.get_connection_string(),
                **engine_kwargs
            )
            
            # Test connection
            connection_test = await self._test_external_connection()
            
            if connection_test["success"]:
                self.is_connected = True
                logger.info(f"✅ Connected to external {config.provider.value} database")
                
                return {
                    "success": True,
                    "message": f"Successfully configured {config.provider.value} database",
                    "connection_info": {
                        "provider": config.provider.value,
                        "engine": config.engine.value,
                        "host": config.host,
                        "database": config.database,
                        "ssl_enabled": config.ssl_enabled
                    },
                    "test_results": connection_test["test_results"]
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to connect to external database",
                    "test_results": connection_test["test_results"]
                }
        
        except Exception as e:
            logger.error(f"Failed to configure external database: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _validate_config(self, config: ExternalDatabaseConfig) -> Dict[str, Any]:
        """Validate external database configuration."""
        errors = []
        
        # Check provider support
        if config.provider not in self.provider_configs:
            errors.append(f"Unsupported provider: {config.provider}")
        else:
            provider_config = self.provider_configs[config.provider]
            
            # Check engine support
            if config.engine not in provider_config["supported_engines"]:
                errors.append(f"Engine {config.engine} not supported by {config.provider}")
            
            # Check SSL requirement
            if provider_config.get("ssl_required") and not config.ssl_enabled:
                errors.append(f"SSL is required for {config.provider}")
        
        # Validate connection parameters
        if not config.host:
            errors.append("Host is required")
        
        if not config.database:
            errors.append("Database name is required")
        
        if not config.username:
            errors.append("Username is required")
        
        if not config.password:
            errors.append("Password is required")
        
        # Validate port
        if config.port <= 0 or config.port > 65535:
            errors.append("Invalid port number")
        
        # Validate pool settings
        if config.pool_size <= 0:
            errors.append("Pool size must be positive")
        
        if config.max_overflow < 0:
            errors.append("Max overflow cannot be negative")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    async def _test_external_connection(self) -> Dict[str, Any]:
        """Test external database connection."""
        if not self.config or not self.engine:
            return {
                "success": False,
                "error": "No configuration or engine available"
            }
        
        test_results = {
            "connection_successful": False,
            "database_accessible": False,
            "permissions_verified": False,
            "ssl_verified": False,
            "version_info": None,
            "response_time_ms": 0,
            "connection_pool_status": {},
            "error_details": None
        }
        
        try:
            import time
            start_time = time.time()
            
            with self.engine.connect() as conn:
                # Test basic connection
                if self.config.engine == DatabaseEngine.POSTGRESQL:
                    result = conn.execute(text("SELECT version(), current_database(), current_user"))
                    row = result.fetchone()
                    test_results["version_info"] = row[0]
                    test_results["database_accessible"] = row[1] == self.config.database
                    
                    # Check SSL
                    ssl_result = conn.execute(text("SHOW ssl"))
                    test_results["ssl_verified"] = ssl_result.fetchone()[0] == "on"
                    
                elif self.config.engine in [DatabaseEngine.MYSQL, DatabaseEngine.MARIADB]:
                    result = conn.execute(text("SELECT VERSION(), DATABASE(), USER()"))
                    row = result.fetchone()
                    test_results["version_info"] = row[0]
                    test_results["database_accessible"] = row[1] == self.config.database
                    
                    # Check SSL
                    ssl_result = conn.execute(text("SHOW STATUS LIKE 'Ssl_cipher'"))
                    ssl_row = ssl_result.fetchone()
                    test_results["ssl_verified"] = bool(ssl_row and ssl_row[1])
                
                # Test permissions
                try:
                    conn.execute(text("CREATE TABLE IF NOT EXISTS netlink_test (id INTEGER PRIMARY KEY)"))
                    conn.execute(text("DROP TABLE IF EXISTS netlink_test"))
                    conn.commit()
                    test_results["permissions_verified"] = True
                except:
                    test_results["permissions_verified"] = False
                
                test_results["connection_successful"] = True
            
            # Get connection pool status
            test_results["connection_pool_status"] = {
                "pool_size": self.engine.pool.size(),
                "checked_in": self.engine.pool.checkedin(),
                "checked_out": self.engine.pool.checkedout(),
                "overflow": self.engine.pool.overflow(),
                "invalid": self.engine.pool.invalid()
            }
            
            test_results["response_time_ms"] = (time.time() - start_time) * 1000
            
            return {
                "success": True,
                "test_results": test_results
            }
        
        except Exception as e:
            test_results["error_details"] = str(e)
            return {
                "success": False,
                "test_results": test_results,
                "error": str(e)
            }
    
    async def get_connection_health(self) -> Dict[str, Any]:
        """Get current connection health status."""
        if not self.is_connected or not self.engine:
            return {
                "status": "disconnected",
                "message": "No active connection"
            }
        
        try:
            # Quick health check
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            # Get pool statistics
            pool_stats = {
                "pool_size": self.engine.pool.size(),
                "checked_in": self.engine.pool.checkedin(),
                "checked_out": self.engine.pool.checkedout(),
                "overflow": self.engine.pool.overflow(),
                "invalid": self.engine.pool.invalid()
            }
            
            return {
                "status": "healthy",
                "provider": self.config.provider.value if self.config else "unknown",
                "engine": self.config.engine.value if self.config else "unknown",
                "pool_stats": pool_stats,
                "ssl_enabled": self.config.ssl_enabled if self.config else False
            }
        
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "provider": self.config.provider.value if self.config else "unknown"
            }
    
    def get_provider_setup_guide(self, provider: DatabaseProvider) -> Dict[str, Any]:
        """Get setup guide for specific provider."""
        guides = {
            DatabaseProvider.AWS_RDS: {
                "steps": [
                    "Create RDS instance in AWS Console",
                    "Configure security groups to allow connections",
                    "Note the endpoint, port, and credentials",
                    "Enable SSL/TLS encryption",
                    "Create database and user if needed"
                ],
                "connection_format": "your-rds-instance.region.rds.amazonaws.com",
                "documentation": "https://docs.aws.amazon.com/rds/"
            },
            DatabaseProvider.SUPABASE: {
                "steps": [
                    "Create project in Supabase dashboard",
                    "Go to Settings > Database",
                    "Copy connection string",
                    "Use connection pooling for production",
                    "Configure row level security if needed"
                ],
                "connection_format": "db.project-ref.supabase.co",
                "documentation": "https://supabase.com/docs/guides/database"
            }
        }
        
        return guides.get(provider, {
            "steps": ["Refer to provider documentation for setup instructions"],
            "connection_format": "provider-specific-format",
            "documentation": "Check provider's official documentation"
        })

    def store_encrypted_connection(self, name: str, config: ExternalDatabaseConfig):
        """Store external database configuration with encryption."""
        if not self.encryption_enabled:
            logger.warning("Encryption not available - storing connection without encryption")
            return

        try:
            connection_string = config.get_connection_string()
            self.encryption_manager.store_encrypted_connection(name, connection_string)

            # Store encrypted config metadata
            config_dict = asdict(config)
            # Remove sensitive data from metadata
            config_dict.pop('password', None)
            config_dict.pop('username', None)

            logger.info(f"Stored encrypted external database connection: {name}")

        except Exception as e:
            logger.error(f"Failed to store encrypted connection: {e}")
            raise

    def get_encrypted_connection(self, name: str) -> str:
        """Retrieve encrypted external database connection."""
        if not self.encryption_enabled:
            raise ValueError("Encryption not available")

        try:
            return self.encryption_manager.get_decrypted_connection(name)
        except Exception as e:
            logger.error(f"Failed to retrieve encrypted connection: {e}")
            raise

    def setup_encrypted_engine(self, config: ExternalDatabaseConfig) -> Engine:
        """Create database engine with encryption support."""
        try:
            connection_string = config.get_connection_string()

            # Create engine with appropriate settings
            engine_kwargs = {
                'echo': False,
                'future': True,
                'pool_pre_ping': True,
                'pool_recycle': config.pool_recycle
            }

            if config.engine == DatabaseEngine.POSTGRESQL:
                engine_kwargs.update({
                    'poolclass': QueuePool,
                    'pool_size': config.pool_size,
                    'max_overflow': config.max_overflow,
                    'pool_timeout': config.pool_timeout
                })
            elif config.engine in [DatabaseEngine.MYSQL, DatabaseEngine.MARIADB]:
                engine_kwargs.update({
                    'poolclass': QueuePool,
                    'pool_size': config.pool_size,
                    'max_overflow': config.max_overflow,
                    'pool_timeout': config.pool_timeout
                })

            engine = create_engine(connection_string, **engine_kwargs)

            # Setup encryption hooks if available
            if self.encryption_enabled:
                self.encryption_manager.setup_engine_encryption(engine)
                logger.info("Database encryption hooks installed for external database")

            return engine

        except Exception as e:
            logger.error(f"Failed to create encrypted engine: {e}")
            raise

    def get_encryption_status(self) -> Dict[str, Any]:
        """Get encryption status for external databases."""
        status = {
            "encryption_enabled": self.encryption_enabled,
            "external_connections_encrypted": 0,
            "encryption_algorithm": "AES-256 (Fernet)" if self.encryption_enabled else None
        }

        if self.encryption_enabled and self.encryption_manager:
            manager_status = self.encryption_manager.get_encryption_status()
            status.update({
                "external_connections_encrypted": manager_status.get("encrypted_connections_count", 0),
                "field_encryption_enabled": manager_status.get("field_encryption_enabled", False),
                "at_rest_encryption_enabled": manager_status.get("at_rest_encryption_enabled", False)
            })

        return status


# Global external database manager
external_db_manager = ExternalDatabaseManager()
