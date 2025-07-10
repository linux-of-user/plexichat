"""
Enhanced Database Abstraction Layer for NetLink.
Supports multiple database types with seamless switching and migration capabilities.
"""

import os
import json
import asyncio
from typing import Dict, List, Any, Optional, Type, Union
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
import logging

try:
    from sqlmodel import SQLModel, Session, create_engine, select
    from sqlalchemy import Engine, MetaData, Table, Column, inspect
    from sqlalchemy.pool import StaticPool
    import asyncpg
    import aiomysql
    import aiosqlite
except ImportError as e:
    print(f"Missing database dependencies: {e}")
    print("Install with: pip install sqlmodel asyncpg aiomysql aiosqlite")

from app.logger_config import logger


class DatabaseType(Enum):
    """Supported database types."""
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MARIADB = "mariadb"


@dataclass
class DatabaseConfig:
    """Database configuration."""
    db_type: DatabaseType
    host: Optional[str] = None
    port: Optional[int] = None
    database: str = "netlink"
    username: Optional[str] = None
    password: Optional[str] = None
    file_path: Optional[str] = None  # For SQLite
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False
    ssl_mode: Optional[str] = None
    charset: str = "utf8mb4"
    
    def get_connection_string(self) -> str:
        """Generate connection string for the database."""
        if self.db_type == DatabaseType.SQLITE:
            file_path = self.file_path or f"{self.database}.db"
            return f"sqlite:///{file_path}"
        
        elif self.db_type == DatabaseType.POSTGRESQL:
            host = self.host or "localhost"
            port = self.port or 5432
            return f"postgresql://{self.username}:{self.password}@{host}:{port}/{self.database}"
        
        elif self.db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
            host = self.host or "localhost"
            port = self.port or 3306
            return f"mysql+pymysql://{self.username}:{self.password}@{host}:{port}/{self.database}?charset={self.charset}"
        
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")


class DatabaseMigration:
    """Database migration management."""
    
    def __init__(self, version: str, description: str, up_sql: str, down_sql: str):
        self.version = version
        self.description = description
        self.up_sql = up_sql
        self.down_sql = down_sql
        self.created_at = datetime.now()


class DatabaseManager:
    """Enhanced database manager with multi-database support."""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.engine: Optional[Engine] = None
        self.session: Optional[Session] = None
        self.migrations: List[DatabaseMigration] = []
        self.is_connected = False
        
        # Database-specific configurations
        self.engine_kwargs = self._get_engine_kwargs()
        
        logger.info(f"🗄️ Database manager initialized for {config.db_type.value}")
    
    def _get_engine_kwargs(self) -> Dict[str, Any]:
        """Get database-specific engine configuration."""
        base_kwargs = {
            "echo": self.config.echo,
            "pool_size": self.config.pool_size,
            "max_overflow": self.config.max_overflow,
            "pool_timeout": self.config.pool_timeout,
            "pool_recycle": self.config.pool_recycle
        }
        
        if self.config.db_type == DatabaseType.SQLITE:
            # SQLite-specific configuration
            base_kwargs.update({
                "poolclass": StaticPool,
                "connect_args": {
                    "check_same_thread": False,
                    "timeout": 30
                }
            })
        
        elif self.config.db_type == DatabaseType.POSTGRESQL:
            # PostgreSQL-specific configuration
            base_kwargs.update({
                "connect_args": {
                    "server_settings": {
                        "application_name": "NetLink",
                        "jit": "off"
                    }
                }
            })
            
            if self.config.ssl_mode:
                base_kwargs["connect_args"]["sslmode"] = self.config.ssl_mode
        
        elif self.config.db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
            # MySQL/MariaDB-specific configuration
            base_kwargs.update({
                "connect_args": {
                    "charset": self.config.charset,
                    "autocommit": False,
                    "connect_timeout": 30
                }
            })
            
            if self.config.ssl_mode:
                base_kwargs["connect_args"]["ssl_disabled"] = self.config.ssl_mode == "disable"
        
        return base_kwargs
    
    async def connect(self) -> bool:
        """Connect to the database."""
        try:
            connection_string = self.config.get_connection_string()
            
            # Create engine
            self.engine = create_engine(connection_string, **self.engine_kwargs)
            
            # Test connection
            with self.engine.connect() as conn:
                if self.config.db_type == DatabaseType.SQLITE:
                    conn.execute("SELECT 1")
                elif self.config.db_type == DatabaseType.POSTGRESQL:
                    conn.execute("SELECT version()")
                elif self.config.db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
                    conn.execute("SELECT VERSION()")
            
            self.is_connected = True
            logger.info(f"✅ Connected to {self.config.db_type.value} database")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to database: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self):
        """Disconnect from the database."""
        try:
            if self.session:
                self.session.close()
                self.session = None
            
            if self.engine:
                self.engine.dispose()
                self.engine = None
            
            self.is_connected = False
            logger.info("🔌 Disconnected from database")
            
        except Exception as e:
            logger.error(f"Error disconnecting from database: {e}")
    
    def get_session(self) -> Session:
        """Get a database session."""
        if not self.is_connected or not self.engine:
            raise RuntimeError("Database not connected")
        
        return Session(self.engine)
    
    async def create_tables(self, models: List[Type[SQLModel]]):
        """Create database tables for the given models."""
        try:
            if not self.engine:
                raise RuntimeError("Database not connected")
            
            # Create all tables
            SQLModel.metadata.create_all(self.engine)
            
            logger.info(f"📋 Created {len(models)} database tables")
            
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise
    
    async def drop_tables(self, models: List[Type[SQLModel]]):
        """Drop database tables for the given models."""
        try:
            if not self.engine:
                raise RuntimeError("Database not connected")
            
            # Drop all tables
            SQLModel.metadata.drop_all(self.engine)
            
            logger.info(f"🗑️ Dropped {len(models)} database tables")
            
        except Exception as e:
            logger.error(f"Failed to drop tables: {e}")
            raise
    
    async def backup_database(self, backup_path: str) -> bool:
        """Create a database backup."""
        try:
            if self.config.db_type == DatabaseType.SQLITE:
                return await self._backup_sqlite(backup_path)
            elif self.config.db_type == DatabaseType.POSTGRESQL:
                return await self._backup_postgresql(backup_path)
            elif self.config.db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
                return await self._backup_mysql(backup_path)
            else:
                logger.error(f"Backup not supported for {self.config.db_type.value}")
                return False
                
        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            return False
    
    async def _backup_sqlite(self, backup_path: str) -> bool:
        """Backup SQLite database."""
        import shutil
        
        try:
            source_path = self.config.file_path or f"{self.config.database}.db"
            
            if os.path.exists(source_path):
                shutil.copy2(source_path, backup_path)
                logger.info(f"📦 SQLite backup created: {backup_path}")
                return True
            else:
                logger.error(f"Source database file not found: {source_path}")
                return False
                
        except Exception as e:
            logger.error(f"SQLite backup failed: {e}")
            return False
    
    async def _backup_postgresql(self, backup_path: str) -> bool:
        """Backup PostgreSQL database."""
        import subprocess
        
        try:
            # Use pg_dump for PostgreSQL backup
            cmd = [
                "pg_dump",
                "-h", self.config.host or "localhost",
                "-p", str(self.config.port or 5432),
                "-U", self.config.username,
                "-d", self.config.database,
                "-f", backup_path,
                "--verbose"
            ]
            
            env = os.environ.copy()
            env["PGPASSWORD"] = self.config.password
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"📦 PostgreSQL backup created: {backup_path}")
                return True
            else:
                logger.error(f"pg_dump failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"PostgreSQL backup failed: {e}")
            return False
    
    async def _backup_mysql(self, backup_path: str) -> bool:
        """Backup MySQL/MariaDB database."""
        import subprocess
        
        try:
            # Use mysqldump for MySQL backup
            cmd = [
                "mysqldump",
                "-h", self.config.host or "localhost",
                "-P", str(self.config.port or 3306),
                "-u", self.config.username,
                f"-p{self.config.password}",
                "--single-transaction",
                "--routines",
                "--triggers",
                self.config.database
            ]
            
            with open(backup_path, 'w') as backup_file:
                result = subprocess.run(cmd, stdout=backup_file, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                logger.info(f"📦 MySQL backup created: {backup_path}")
                return True
            else:
                logger.error(f"mysqldump failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"MySQL backup failed: {e}")
            return False
    
    async def restore_database(self, backup_path: str) -> bool:
        """Restore database from backup."""
        try:
            if self.config.db_type == DatabaseType.SQLITE:
                return await self._restore_sqlite(backup_path)
            elif self.config.db_type == DatabaseType.POSTGRESQL:
                return await self._restore_postgresql(backup_path)
            elif self.config.db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
                return await self._restore_mysql(backup_path)
            else:
                logger.error(f"Restore not supported for {self.config.db_type.value}")
                return False
                
        except Exception as e:
            logger.error(f"Database restore failed: {e}")
            return False
    
    async def _restore_sqlite(self, backup_path: str) -> bool:
        """Restore SQLite database."""
        import shutil
        
        try:
            target_path = self.config.file_path or f"{self.config.database}.db"
            
            if os.path.exists(backup_path):
                # Disconnect first
                await self.disconnect()
                
                # Copy backup to target location
                shutil.copy2(backup_path, target_path)
                
                # Reconnect
                await self.connect()
                
                logger.info(f"🔄 SQLite database restored from: {backup_path}")
                return True
            else:
                logger.error(f"Backup file not found: {backup_path}")
                return False
                
        except Exception as e:
            logger.error(f"SQLite restore failed: {e}")
            return False
    
    async def _restore_postgresql(self, backup_path: str) -> bool:
        """Restore PostgreSQL database."""
        import subprocess
        
        try:
            # Use psql for PostgreSQL restore
            cmd = [
                "psql",
                "-h", self.config.host or "localhost",
                "-p", str(self.config.port or 5432),
                "-U", self.config.username,
                "-d", self.config.database,
                "-f", backup_path,
                "--verbose"
            ]
            
            env = os.environ.copy()
            env["PGPASSWORD"] = self.config.password
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"🔄 PostgreSQL database restored from: {backup_path}")
                return True
            else:
                logger.error(f"psql restore failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"PostgreSQL restore failed: {e}")
            return False
    
    async def _restore_mysql(self, backup_path: str) -> bool:
        """Restore MySQL/MariaDB database."""
        import subprocess
        
        try:
            # Use mysql for MySQL restore
            cmd = [
                "mysql",
                "-h", self.config.host or "localhost",
                "-P", str(self.config.port or 3306),
                "-u", self.config.username,
                f"-p{self.config.password}",
                self.config.database
            ]
            
            with open(backup_path, 'r') as backup_file:
                result = subprocess.run(cmd, stdin=backup_file, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                logger.info(f"🔄 MySQL database restored from: {backup_path}")
                return True
            else:
                logger.error(f"mysql restore failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"MySQL restore failed: {e}")
            return False
    
    async def migrate_to_database(self, target_config: DatabaseConfig) -> bool:
        """Migrate data to a different database type."""
        try:
            logger.info(f"🔄 Starting migration from {self.config.db_type.value} to {target_config.db_type.value}")
            
            # Create target database manager
            target_manager = DatabaseManager(target_config)
            
            # Connect to target database
            if not await target_manager.connect():
                logger.error("Failed to connect to target database")
                return False
            
            # Get table metadata from source
            inspector = inspect(self.engine)
            table_names = inspector.get_table_names()
            
            logger.info(f"📋 Found {len(table_names)} tables to migrate")
            
            # Migrate each table
            for table_name in table_names:
                await self._migrate_table(table_name, target_manager)
            
            await target_manager.disconnect()
            
            logger.info("✅ Database migration completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Database migration failed: {e}")
            return False
    
    async def _migrate_table(self, table_name: str, target_manager: 'DatabaseManager'):
        """Migrate a single table to target database."""
        try:
            # Get table metadata
            metadata = MetaData()
            metadata.reflect(bind=self.engine)
            table = metadata.tables[table_name]
            
            # Create table in target database
            table.create(target_manager.engine, checkfirst=True)
            
            # Copy data
            with self.engine.connect() as source_conn:
                with target_manager.engine.connect() as target_conn:
                    # Read data from source
                    result = source_conn.execute(table.select())
                    rows = result.fetchall()
                    
                    if rows:
                        # Insert data into target
                        target_conn.execute(table.insert(), [dict(row) for row in rows])
                        target_conn.commit()
            
            logger.info(f"📦 Migrated table: {table_name} ({len(rows) rows)")
            
        except Exception as e:
            logger.error(f"Failed to migrate table {table_name}: {e}")
            raise
    
    async def get_database_info(self) -> Dict[str, Any]:
        """Get database information and statistics."""
        try:
            if not self.engine:
                return {"error": "Database not connected"}
            
            info = {
                "database_type": self.config.db_type.value,
                "database_name": self.config.database,
                "connection_string": self.config.get_connection_string().split('@')[0] + "@***",  # Hide credentials
                "is_connected": self.is_connected,
                "engine_info": {
                    "pool_size": self.config.pool_size,
                    "max_overflow": self.config.max_overflow,
                    "pool_timeout": self.config.pool_timeout
                }
            }
            
            # Get table information
            inspector = inspect(self.engine)
            tables = inspector.get_table_names()
            
            table_info = []
            for table_name in tables:
                columns = inspector.get_columns(table_name)
                table_info.append({
                    "name": table_name,
                    "columns": len(columns),
                    "column_names": [col["name"] for col in columns]
                })
            
            info["tables"] = table_info
            info["table_count"] = len(tables)
            
            # Get database-specific information
            if self.config.db_type == DatabaseType.SQLITE:
                info["file_path"] = self.config.file_path or f"{self.config.database}.db"
                if os.path.exists(info["file_path"]):
                    info["file_size"] = os.path.getsize(info["file_path"])
            
            elif self.config.db_type == DatabaseType.POSTGRESQL:
                info["host"] = self.config.host
                info["port"] = self.config.port
                
                # Get PostgreSQL version
                with self.engine.connect() as conn:
                    result = conn.execute("SELECT version()")
                    info["version"] = result.fetchone()[0]
            
            elif self.config.db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
                info["host"] = self.config.host
                info["port"] = self.config.port
                info["charset"] = self.config.charset
                
                # Get MySQL/MariaDB version
                with self.engine.connect() as conn:
                    result = conn.execute("SELECT VERSION()")
                    info["version"] = result.fetchone()[0]
            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get database info: {e}")
            return {"error": str(e)}
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test database connection and performance."""
        try:
            start_time = datetime.now()
            
            # Test basic connection
            with self.engine.connect() as conn:
                if self.config.db_type == DatabaseType.SQLITE:
                    result = conn.execute("SELECT 1 as test")
                elif self.config.db_type == DatabaseType.POSTGRESQL:
                    result = conn.execute("SELECT 1 as test, now() as timestamp")
                elif self.config.db_type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
                    result = conn.execute("SELECT 1 as test, NOW() as timestamp")
                
                test_result = result.fetchone()
            
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds() * 1000  # milliseconds
            
            return {
                "success": True,
                "response_time_ms": round(response_time, 2),
                "test_result": dict(test_result) if test_result else None,
                "timestamp": end_time.isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }


def create_database_manager(config_path: str = "config/database.json") -> DatabaseManager:
    """Create database manager from configuration file."""
    try:
        # Load configuration
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config_data = json.load(f)
        else:
            # Create default configuration
            config_data = {
                "db_type": "sqlite",
                "database": "netlink",
                "file_path": "data/netlink.db",
                "pool_size": 10,
                "echo": False
            }
            
            # Ensure config directory exists
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"📝 Created default database config: {config_path}")
        
        # Create database config
        db_type = DatabaseType(config_data["db_type"])
        config = DatabaseConfig(db_type=db_type, **{k: v for k, v in config_data.items() if k != "db_type"})
        
        # Ensure database directory exists for SQLite
        if db_type == DatabaseType.SQLITE and config.file_path:
            os.makedirs(os.path.dirname(config.file_path), exist_ok=True)
        
        return DatabaseManager(config)
        
    except Exception as e:
        logger.error(f"Failed to create database manager: {e}")
        # Fallback to SQLite
        config = DatabaseConfig(
            db_type=DatabaseType.SQLITE,
            database="netlink",
            file_path="data/netlink.db"
        )
        return DatabaseManager(config)


# Global database manager instance
database_manager = None


async def get_database_manager() -> DatabaseManager:
    """Get the global database manager instance."""
    global database_manager

    if database_manager is None:
        database_manager = create_database_manager()
        await database_manager.connect()

    return database_manager


async def initialize_database():
    """Initialize the database system."""
    try:
        manager = await get_database_manager()

        if manager.is_connected:
            logger.info("🗄️ Database system initialized successfully")
            return True
        else:
            logger.error("❌ Failed to initialize database system")
            return False

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False
