import asyncio
import json
import logging
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from sqlmodel import Session, SQLModel
from sqlalchemy import create_engine, text

from plexichat.app.models.guild import Guild  # type: ignore
from plexichat.app.models.message import Message  # type: ignore
from plexichat.app.models.user import User  # type: ignore
from plexichat.core.config import settings

"""
PlexiChat Database Setup Wizard
Comprehensive database configuration and setup system with support for external databases.
"""

logger = logging.getLogger(__name__)

class DatabaseType(str, Enum):
    """Supported database types."""
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MARIADB = "mariadb"

class SetupStep(str, Enum):
    """Setup wizard steps."""
    WELCOME = "welcome"
    DATABASE_TYPE = "database_type"
    CONNECTION_DETAILS = "connection_details"
    AUTHENTICATION = "authentication"
    ADVANCED_SETTINGS = "advanced_settings"
    TEST_CONNECTION = "test_connection"
    INITIALIZE_SCHEMA = "initialize_schema"
    MIGRATION = "migration"
    COMPLETE = "complete"

@dataclass
class DatabaseConnection:
    """Database connection configuration."""
    db_type: DatabaseType
    host: Optional[str] = None
    port: Optional[int] = None
    database: str = "plexichat"
    username: Optional[str] = None
    password: Optional[str] = None
    file_path: Optional[str] = None  # For SQLite

    # Advanced settings
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    ssl_mode: Optional[str] = None
    charset: str = "utf8mb4"

    # Connection options
    connect_timeout: int = 30
    read_timeout: int = 30
    write_timeout: int = 30

    def get_connection_string(self) -> str:
        """Generate connection string for the database."""
        if self.db_type == DatabaseType.SQLITE:
            if self.file_path:
                return f"sqlite:///{self.file_path}"
            return "sqlite:///data/plexichat.db"

        elif self.db_type == DatabaseType.POSTGRESQL:
            base_url = f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
            params = []
            if self.ssl_mode:
                params.append(f"sslmode={self.ssl_mode}")
            if self.connect_timeout:
                params.append(f"connect_timeout={self.connect_timeout}")

            if params:
                base_url += "?" + "&".join(params)
            return base_url

        elif self.db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
            base_url = f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
            params = []
            if self.charset:
                params.append(f"charset={self.charset}")
            if self.ssl_mode:
                params.append(f"ssl_mode={self.ssl_mode}")

            if params:
                base_url += "?" + "&".join(params)
            return base_url

        raise ValueError(f"Unsupported database type: {self.db_type}")

@dataclass
class SetupProgress:
    """Setup wizard progress tracking."""
    current_step: SetupStep = SetupStep.WELCOME
    completed_steps: Optional[List[SetupStep]] = None
    connection_config: Optional[DatabaseConnection] = None
    test_results: Optional[Dict[str, Any]] = None
    errors: Optional[List[str]] = None
    warnings: Optional[List[str]] = None

    def __post_init__(self):
        if self.completed_steps is None:
            self.completed_steps = []
        if self.test_results is None:
            self.test_results = {}
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []

class DatabaseSetupWizard:
    """Comprehensive database setup wizard."""

    def __init__(self):
        self.progress = SetupProgress()
        from pathlib import Path
self.config_dir = Path("config")
        self.config_dir.mkdir(exist_ok=True)

        # Database type configurations
        self.db_configs = {
            DatabaseType.SQLITE: {
                "name": "SQLite",
                "description": "Lightweight file-based database (recommended for development)",
                "default_port": None,
                "requires_server": False,
                "features": ["transactions", "json", "full_text_search"],
                "pros": ["No server required", "Zero configuration", "Fast for small datasets"],
                "cons": ["Limited concurrent writes", "No network access", "Single file"]
            },
            DatabaseType.POSTGRESQL: {
                "name": "PostgreSQL",
                "description": "Advanced open-source relational database (recommended for production)",
                "default_port": 5432,
                "requires_server": True,
                "features": ["transactions", "json", "arrays", "full_text_search", "extensions"],
                "pros": ["Excellent performance", "Advanced features", "Strong consistency"],
                "cons": ["Requires server setup", "More complex configuration"]
            },
            DatabaseType.MYSQL: {
                "name": "MySQL",
                "description": "Popular open-source relational database",
                "default_port": 3306,
                "requires_server": True,
                "features": ["transactions", "json", "full_text_search"],
                "pros": ["Wide compatibility", "Good performance", "Large community"],
                "cons": ["Requires server setup", "Some feature limitations"]
            },
            DatabaseType.MARIADB: {
                "name": "MariaDB",
                "description": "MySQL-compatible database with enhanced features",
                "default_port": 3306,
                "requires_server": True,
                "features": ["transactions", "json", "full_text_search", "enhanced_storage"],
                "pros": ["MySQL compatible", "Enhanced features", "Active development"],
                "cons": ["Requires server setup", "Less widespread than MySQL"]
            }
        }

    def _ensure_lists_initialized(self):
        """Ensure progress lists are initialized."""
        if self.progress.completed_steps is None:
            self.progress.completed_steps = []
        if self.progress.errors is None:
            self.progress.errors = []
        if self.progress.warnings is None:
            self.progress.warnings = []
        if self.progress.test_results is None:
            self.progress.test_results = {}

    def _add_completed_step(self, step: SetupStep):
        """Safely add a completed step."""
        self._ensure_lists_initialized()
        assert self.progress.completed_steps is not None
        if step not in self.progress.completed_steps:
            self.progress.completed_steps.append(step)

    def _add_error(self, error: str):
        """Safely add an error."""
        self._ensure_lists_initialized()
        assert self.progress.errors is not None
        self.progress.errors.append(error)

    def get_wizard_status(self) -> Dict[str, Any]:
        """Get current wizard status."""
        completed_steps = self.progress.completed_steps or []
        errors = self.progress.errors or []
        warnings = self.progress.warnings or []

        return {}}
            "current_step": self.progress.current_step.value,
            "completed_steps": [step.value for step in completed_steps],
            "total_steps": len(SetupStep),
            "progress_percentage": (len(completed_steps) / len(SetupStep)) * 100,
            "has_errors": len(errors) > 0,
            "has_warnings": len(warnings) > 0,
            "connection_configured": self.progress.connection_config is not None,
            "test_results": self.progress.test_results or {}
        }

    def get_database_types(self) -> Dict[str, Any]:
        """Get available database types with descriptions."""
        return {}}
            "database_types": [
                {
                    "type": db_type.value,
                    "config": config,
                    "recommended": db_type == DatabaseType.POSTGRESQL
                }
                for db_type, config in self.db_configs.items()
            ]
        }

    def set_database_type(self, db_type: str) -> Dict[str, Any]:
        """Set the database type and initialize connection config."""
        try:
            database_type = DatabaseType(db_type)

            # Initialize connection config with defaults
            config = self.db_configs[database_type]

            self.progress.connection_config = DatabaseConnection()
                db_type=database_type,
                port=config["default_port"],
                database="plexichat"
            )

            # Mark step as completed
            if self.progress.completed_steps is None:
                self.progress.completed_steps = []
            if SetupStep.DATABASE_TYPE not in self.progress.completed_steps:
                self.progress.completed_steps.append(SetupStep.DATABASE_TYPE)

            self.progress.current_step = SetupStep.CONNECTION_DETAILS

            return {}}
                "success": True,
                "message": f"Database type set to {config['name']}",
                "next_step": self.progress.current_step.value,
                "requires_server": config["requires_server"],
                "default_settings": {
                    "port": config["default_port"],
                    "database": "plexichat"
                }
            }

        except ValueError:
            error_msg = f"Invalid database type: {db_type}"
            if self.progress.errors is None:
                self.progress.errors = []
            if self.progress.errors is None:
                self.progress.errors = []
            if self.progress.errors is None:
                self.progress.errors = []
            if self.progress.errors is None:
                self.progress.errors = []
            if self.progress.errors is None:
                self.progress.errors = []
            if self.progress.errors is None:
                self.progress.errors = []
            self.progress.errors.append(error_msg)
            return {}}
                "success": False,
                "error": error_msg,
                "valid_types": [t.value for t in DatabaseType]
            }

    def set_connection_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Set database connection details."""
        if not self.progress.connection_config:
            return {}}
                "success": False,
                "error": "Database type must be selected first"
            }

        try:
            # Update connection config
            config = self.progress.connection_config

            if config.db_type == DatabaseType.SQLITE:
                config.file_path = details.get("file_path", "data/plexichat.db")
            else:
                config.host = details.get("host", "localhost")
                config.port = details.get("port", config.port)
                config.database = details.get("database", "plexichat")

            # Mark step as completed
            if self.progress.completed_steps is None:
                self.progress.completed_steps = []
            if self.progress.completed_steps is None:
                self.progress.completed_steps = []
            if self.progress.completed_steps is None:
                self.progress.completed_steps = []
            if self.progress.completed_steps is None:
                self.progress.completed_steps = []
            if SetupStep.CONNECTION_DETAILS not in self.progress.completed_steps:
                self.progress.completed_steps.append(SetupStep.CONNECTION_DETAILS)

            # Determine next step
            if config.db_type == DatabaseType.SQLITE:
                self.progress.current_step = SetupStep.ADVANCED_SETTINGS
            else:
                self.progress.current_step = SetupStep.AUTHENTICATION

            return {}}
                "success": True,
                "message": "Connection details configured",
                "next_step": self.progress.current_step.value,
                "connection_string_preview": self._get_safe_connection_string()
            }

        except Exception as e:
            error_msg = f"Failed to set connection details: {e}"
            if self.progress.errors is None:
                self.progress.errors = []
            self.progress.errors.append(error_msg)
            return {}}
                "success": False,
                "error": error_msg
            }

    def set_authentication(self, auth_details: Dict[str, Any]) -> Dict[str, Any]:
        """Set database authentication details."""
        if not self.progress.connection_config:
            return {}}
                "success": False,
                "error": "Connection details must be configured first"
            }

        try:
            config = self.progress.connection_config
            config.username = auth_details.get("username")
            config.password = auth_details.get("password")

            # Mark step as completed
            self._add_completed_step(SetupStep.AUTHENTICATION)

            self.progress.current_step = SetupStep.ADVANCED_SETTINGS

            return {}}
                "success": True,
                "message": "Authentication configured",
                "next_step": self.progress.current_step.value
            }

        except Exception as e:
            error_msg = f"Failed to set authentication: {e}"
            self._add_error(error_msg)
            return {}}
                "success": False,
                "error": error_msg
            }

    def set_advanced_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        """Set advanced database from plexichat.core.config import settings
settings."""
        if not self.progress.connection_config:
            return {}}
                "success": False,
                "error": "Connection must be configured first"
            }

        try:
            config = self.progress.connection_config

            # Update advanced settings
            config.from plexichat.core.config import settings
pool_size = settings().get("pool_size", config.pool_size)
            config.from plexichat.core.config import settings
max_overflow = settings().get("max_overflow", config.max_overflow)
            config.from plexichat.core.config import settings
pool_timeout = settings().get("pool_timeout", config.pool_timeout)
            config.from plexichat.core.config import settings
pool_recycle = settings().get("pool_recycle", config.pool_recycle)
            config.from plexichat.core.config import settings
ssl_mode = settings().get("ssl_mode", config.ssl_mode)
            config.from plexichat.core.config import settings
charset = settings().get("charset", config.charset)
            config.from plexichat.core.config import settings
connect_timeout = settings().get("connect_timeout", config.connect_timeout)

            # Mark step as completed
            self._add_completed_step(SetupStep.ADVANCED_SETTINGS)

            self.progress.current_step = SetupStep.TEST_CONNECTION

            return {}}
                "success": True,
                "message": "Advanced settings configured",
                "next_step": self.progress.current_step.value,
                "settings_summary": {
                    "pool_size": config.pool_size,
                    "ssl_enabled": bool(config.ssl_mode),
                    "charset": config.charset
                }
            }

        except Exception as e:
            error_msg = f"Failed to set advanced settings: {e}"
            self._add_error(error_msg)
            return {}}
                "success": False,
                "error": error_msg
            }

    def _get_safe_connection_string(self) -> str:
        """Get connection string with password masked."""
        if not self.progress.connection_config:
            return ""

        conn_str = self.progress.connection_config.get_connection_string()

        # Mask password in connection string
        if self.progress.connection_config.password:
            conn_str = conn_str.replace()
                self.progress.connection_config.password,
                "***"
            )

        return conn_str

    async def test_connection(self) -> Dict[str, Any]:
        """Test database connection."""
        if not self.progress.connection_config:
            return {}}
                "success": False,
                "error": "Connection must be configured first"
            }

        try:
            config = self.progress.connection_config
            config.get_connection_string()

            # Test connection based on database type
            test_results = {
                "connection_successful": False,
                "database_exists": False,
                "permissions_ok": False,
                "version_info": None,
                "response_time_ms": 0,
                "error_details": None
            }

            start_time = time.time()

            if config.db_type == DatabaseType.SQLITE:
                test_results.update(await self._test_sqlite_connection(config))
            elif config.db_type == DatabaseType.POSTGRESQL:
                test_results.update(await self._test_postgresql_connection(config))
            elif config.db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
                test_results.update(await self._test_mysql_connection(config))

            test_results["response_time_ms"] = (time.time() - start_time) * 1000

            # Store test results
            self.progress.test_results = test_results

            if test_results["connection_successful"]:
                # Mark step as completed
                self._add_completed_step(SetupStep.TEST_CONNECTION)

                self.progress.current_step = SetupStep.INITIALIZE_SCHEMA

                return {}}
                    "success": True,
                    "message": "Database connection successful",
                    "test_results": test_results,
                    "next_step": self.progress.current_step.value
                }
            else:
                return {}}
                    "success": False,
                    "error": "Database connection failed",
                    "test_results": test_results,
                    "troubleshooting": self._get_troubleshooting_tips(config.db_type)
                }

        except Exception as e:
            error_msg = f"Connection test failed: {e}"
            self._add_error(error_msg)
            return {}}
                "success": False,
                "error": error_msg,
                "troubleshooting": self._get_troubleshooting_tips(config.db_type)
            }

    async def _test_sqlite_connection(self, config: DatabaseConnection) -> Dict[str, Any]:
        """Test SQLite connection."""
        try:
            # Ensure directory exists
            from pathlib import Path

            self.db_path = Path(config.file_path or "data/plexichat.db")
            db_path.parent.mkdir(parents=True, exist_ok=True)

            # Test connection
            engine = create_engine(config.get_connection_string())

            with engine.connect() as conn:
                result = conn.execute(text("SELECT sqlite_version()"))
                row = result.fetchone()
                version = row[0] if row else "Unknown"

                # Test write permissions
                conn.execute(text("CREATE TABLE IF NOT EXISTS test_table (id INTEGER)"))
                conn.execute(text("DROP TABLE IF EXISTS test_table"))
                conn.commit()

            return {}}
                "connection_successful": True,
                "database_exists": True,
                "permissions_ok": True,
                "version_info": f"SQLite {version}"
            }

        except Exception as e:
            return {}}
                "connection_successful": False,
                "error_details": str(e)
            }

    async def _test_postgresql_connection(self, config: DatabaseConnection) -> Dict[str, Any]:
        """Test PostgreSQL connection."""
        try:
            engine = create_engine(config.get_connection_string())

            with engine.connect() as conn:
                # Test basic connection
                result = conn.execute(text("SELECT version()"))
                row = result.fetchone()
                version = row[0] if row else "Unknown"

                # Check if database exists
                result = conn.execute(text("SELECT current_database()"))
                row = result.fetchone()
                row[0] if row else "Unknown"

                # Test permissions
                conn.execute(text("CREATE TABLE IF NOT EXISTS test_table (id SERIAL PRIMARY KEY)"))
                conn.execute(text("DROP TABLE IF EXISTS test_table"))
                conn.commit()

            return {}}
                "connection_successful": True,
                "database_exists": True,
                "permissions_ok": True,
                "version_info": version.split(' on ')[0]  # Clean up version string
            }

        except Exception as e:
            return {}}
                "connection_successful": False,
                "error_details": str(e)
            }

    async def _test_mysql_connection(self, config: DatabaseConnection) -> Dict[str, Any]:
        """Test MySQL/MariaDB connection."""
        try:
            engine = create_engine(config.get_connection_string())

            with engine.connect() as conn:
                # Test basic connection
                result = conn.execute(text("SELECT VERSION()"))
                row = result.fetchone()
                version = row[0] if row else "Unknown"

                # Check database
                result = conn.execute(text("SELECT DATABASE()"))
                row = result.fetchone()
                row[0] if row else "Unknown"

                # Test permissions
                conn.execute(text("CREATE TABLE IF NOT EXISTS test_table (id INT AUTO_INCREMENT PRIMARY KEY)"))
                conn.execute(text("DROP TABLE IF EXISTS test_table"))
                conn.commit()

            return {}}
                "connection_successful": True,
                "database_exists": True,
                "permissions_ok": True,
                "version_info": version
            }

        except Exception as e:
            return {}}
                "connection_successful": False,
                "error_details": str(e)
            }

    def _get_troubleshooting_tips(self, db_type: DatabaseType) -> List[str]:
        """Get troubleshooting tips for database connection issues."""
        common_tips = [
            "Verify the database server is running",
            "Check network connectivity to the database host",
            "Ensure firewall allows connections on the database port",
            "Verify username and password are correct"
        ]

        if db_type == DatabaseType.SQLITE:
            return [
                "Ensure the directory for the database file exists",
                "Check file permissions for the database directory",
                "Verify disk space is available"
            ]
        elif db_type == DatabaseType.POSTGRESQL:
            return common_tips + [
                "Check PostgreSQL server configuration (postgresql.conf)",
                "Verify pg_hba.conf allows connections from your IP",
                "Ensure the database exists or you have CREATE privileges",
                "Try connecting with psql command line tool first"
            ]
        elif db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
            return common_tips + [
                "Check MySQL/MariaDB server configuration",
                "Verify user has proper privileges (GRANT statements)",
                "Ensure the database exists or you have CREATE privileges",
                "Try connecting with mysql command line tool first"
            ]

        return common_tips

    async def initialize_schema(self, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Initialize database schema."""
        test_results = self.progress.test_results or {}
        if not self.progress.connection_config or not test_results.get("connection_successful"):
            return {}}
                "success": False,
                "error": "Database connection must be tested successfully first"
            }

        try:
            options = options or {}
            create_sample_data = options.get("create_sample_data", False)
            drop_existing = options.get("drop_existing", False)

            config = self.progress.connection_config
            connection_string = config.get_connection_string()

            # Initialize schema
            schema_results = {
                "tables_created": 0,
                "indexes_created": 0,
                "sample_data_created": False,
                "migration_applied": False,
                "errors": []
            }

            engine = create_engine(connection_string)

            # Import models to ensure they're registered
            try:
            except ImportError:
                logger.warning("PlexiChat models not available, skipping model registration")

            # Create all tables
            if drop_existing:
                SQLModel.metadata.drop_all(engine)

            SQLModel.metadata.create_all(engine)

            # Count created tables
            with engine.connect() as conn:
                if config.db_type == DatabaseType.SQLITE:
                    result = conn.execute(text("SELECT COUNT(*) FROM sqlite_master WHERE type='table'"))
                elif config.db_type == DatabaseType.POSTGRESQL:
                    result = conn.execute(text("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'"))
                elif config.db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
                    result = conn.execute(text("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()"))

                row = result.fetchone()
                schema_results["tables_created"] = row[0] if row else 0

            # Create sample data if requested
            if create_sample_data:
                schema_results["sample_data_created"] = await self._create_sample_data(engine)

            # Mark step as completed
            self._add_completed_step(SetupStep.INITIALIZE_SCHEMA)

            self.progress.current_step = SetupStep.COMPLETE

            return {}}
                "success": True,
                "message": "Database schema initialized successfully",
                "schema_results": schema_results,
                "next_step": self.progress.current_step.value
            }

        except Exception as e:
            error_msg = f"Schema initialization failed: {e}"
            self._add_error(error_msg)
            return {}}
                "success": False,
                "error": error_msg
            }

    async def _create_sample_data(self, engine) -> bool:
        """Create sample data for testing."""
        try:
            with Session(engine) as session:
                # Create sample admin user
                try:
                except ImportError:
                    logger.warning("User model not available")
                    return False
                admin_user = User()
                    username="admin",
                    email="admin@plexichat.local",
                    is_admin=True,
                    is_verified=True
                )
                session.add(admin_user)

                # Create sample guild
                try:
                except ImportError:
                    logger.warning("Guild model not available")
                    return False
                sample_guild = Guild()
                    name="General",
                    description="Default server for PlexiChat",
                    owner_id=1  # Admin user
                )
                session.add(sample_guild)

                # Create sample message
                try:
                except ImportError:
                    logger.warning("Message model not available")
                    return False
                welcome_message = Message()
                    content="Welcome to PlexiChat! This is a sample message.",
                    author_id=1,
                    guild_id=1
                )
                session.add(welcome_message)

                session.commit()

            return True

        except Exception as e:
            logger.error(f"Failed to create sample data: {e}")
            return False

    def save_configuration(self) -> Dict[str, Any]:
        """Save the database configuration to files."""
        if not self.progress.connection_config:
            return {}}
                "success": False,
                "error": "No configuration to save"
            }

        try:
            config = self.progress.connection_config

            # Create database configuration
            db_config = {
                "database": {
                    "type": config.db_type.value,
                    "url": config.get_connection_string(),
                    "pool_size": config.pool_size,
                    "max_overflow": config.max_overflow,
                    "pool_timeout": config.pool_timeout,
                    "pool_recycle": config.pool_recycle,
                    "echo": False
                },
                "setup": {
                    "completed_at": asyncio.get_event_loop().time(),
                    "wizard_version": "1.0.0",
                    "test_results": self.progress.test_results
                }
            }

            # Save to YAML file
            config_file = self.config_dir / "database.yaml"
            with open(config_file, 'w') as f:
                yaml.dump(db_config, f, default_flow_style=False, indent=2)

            # Save to JSON file (backup)
            json_file = self.config_dir / "database.json"
            with open(json_file, 'w') as f:
                json.dump(db_config, f, indent=2)

            # Update environment file
            from pathlib import Path

            self.env_file = Path(".env")
            env_content = []

            if env_file.exists():
                with open(env_file, 'r') as f:
                    env_content = f.readlines()

            # Remove existing DATABASE_URL
            env_content = [line for line in env_content if not line.startswith('DATABASE_URL=')]

            # Add new DATABASE_URL
            env_content.append(f'DATABASE_URL={config.get_connection_string()}\n')

            with open(env_file, 'w') as f:
                f.writelines(env_content)

            # Mark setup as complete
            if self.progress.completed_steps is None:
                self.progress.completed_steps = []
            if SetupStep.COMPLETE not in self.progress.completed_steps:
                self.progress.completed_steps.append(SetupStep.COMPLETE)

            return {}}
                "success": True,
                "message": "Database configuration saved successfully",
                "files_created": [
                    str(config_file),
                    str(json_file),
                    str(env_file)
                ],
                "connection_string": self._get_safe_connection_string()
            }

        except Exception as e:
            error_msg = f"Failed to save configuration: {e}"
            if self.progress.errors is None:
                self.progress.errors = []
            self.progress.errors.append(error_msg)
            return {}}
                "success": False,
                "error": error_msg
            }

    def get_setup_summary(self) -> Dict[str, Any]:
        """Get complete setup summary."""
        return {}}
            "wizard_status": self.get_wizard_status(),
            "configuration": asdict(self.progress.connection_config) if self.progress.connection_config else None,
            "test_results": self.progress.test_results,
            "errors": self.progress.errors,
            "warnings": self.progress.warnings,
            "next_steps": self._get_next_steps()
        }

    def _get_next_steps(self) -> List[str]:
        """Get recommended next steps after setup."""
        if self.progress.current_step == SetupStep.COMPLETE:
            return [
                "Restart the PlexiChat application to use the new database",
                "Verify all features work correctly with the new database",
                "Consider setting up regular database backups",
                "Monitor database performance and optimize as needed"
            ]
        else:
            return [
                f"Complete the current step: {self.progress.current_step.value}",
                "Follow the wizard prompts to finish setup"
            ]

    def reset_wizard(self) -> Dict[str, Any]:
        """Reset the wizard to start over."""
        self.progress = SetupProgress()

        return {}}
            "success": True,
            "message": "Wizard reset successfully",
            "current_step": self.progress.current_step.value
        }

    def get_migration_options(self, source_db_url: str) -> Dict[str, Any]:
        """Get options for migrating from existing database."""
        try:
            # Analyze source database
            source_engine = create_engine(source_db_url)

            migration_info = {
                "source_type": source_db_url.split('://')[0],
                "tables_found": [],
                "estimated_records": 0,
                "migration_complexity": "simple",
                "estimated_time_minutes": 5,
                "recommendations": []
            }

            with source_engine.connect() as conn:
                # Get table information
                if migration_info["source_type"] == "sqlite":
                    result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
                    tables = [row[0] for row in result.fetchall()]
                elif migration_info["source_type"] == "postgresql":
                    result = conn.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='public'"))
                    tables = [row[0] for row in result.fetchall()]
                elif migration_info["source_type"] in ["mysql", "mariadb"]:
                    result = conn.execute(text("SHOW TABLES"))
                    tables = [row[0] for row in result.fetchall()]

                migration_info["tables_found"] = tables

                # Estimate complexity
                if len(tables) > 10:
                    migration_info["migration_complexity"] = "complex"
                    migration_info["estimated_time_minutes"] = 30
                elif len(tables) > 5:
                    migration_info["migration_complexity"] = "moderate"
                    migration_info["estimated_time_minutes"] = 15

            return {}}
                "success": True,
                "migration_info": migration_info
            }

        except Exception as e:
            return {}}
                "success": False,
                "error": f"Failed to analyze source database: {e}"
            }


# Global wizard instance
database_wizard = DatabaseSetupWizard()
