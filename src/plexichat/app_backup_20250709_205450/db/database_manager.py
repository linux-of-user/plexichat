# app/db/database_manager.py
"""
Enhanced database management with support for multiple database types,
connection pooling, migrations, and advanced features.
"""

import os
import re
from typing import Dict, Any, Optional, List, Type, Union
from urllib.parse import urlparse
from sqlmodel import create_engine, SQLModel, Session, text
from sqlalchemy import event, pool
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool, NullPool
import sqlite3

from app.logger_config import settings, logger
from app.core.database.multi_backend import db_manager as enhanced_db_manager
from app.core.database.migrations import migration_manager


class DatabaseConfig:
    """Database configuration with support for multiple database types."""
    
    SUPPORTED_DATABASES = {
        'postgresql': {
            'driver': 'psycopg2',
            'port': 5432,
            'features': ['transactions', 'json', 'arrays', 'full_text_search']
        },
        'mysql': {
            'driver': 'pymysql',
            'port': 3306,
            'features': ['transactions', 'json']
        },
        'sqlite': {
            'driver': 'sqlite3',
            'port': None,
            'features': ['transactions', 'json']
        },
        'mssql': {
            'driver': 'pyodbc',
            'port': 1433,
            'features': ['transactions', 'json']
        }
    }
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.parsed_url = urlparse(database_url)
        self.database_type = self._detect_database_type()
        self.config = self._get_database_config()
    
    def _detect_database_type(self) -> str:
        """Detect database type from URL scheme."""
        scheme = self.parsed_url.scheme.lower()
        
        if scheme.startswith('postgresql'):
            return 'postgresql'
        elif scheme.startswith('mysql'):
            return 'mysql'
        elif scheme.startswith('sqlite'):
            return 'sqlite'
        elif scheme.startswith('mssql') or scheme.startswith('sqlserver'):
            return 'mssql'
        else:
            raise ValueError(f"Unsupported database type: {scheme}")
    
    def _get_database_config(self) -> Dict[str, Any]:
        """Get configuration for the detected database type."""
        if self.database_type not in self.SUPPORTED_DATABASES:
            raise ValueError(f"Database type {self.database_type} is not supported")
        
        return self.SUPPORTED_DATABASES[self.database_type]
    
    def get_engine_kwargs(self) -> Dict[str, Any]:
        """Get engine-specific configuration."""
        kwargs = {
            'echo': settings.LOG_LEVEL == "DEBUG",
            'future': True
        }
        
        if self.database_type == 'postgresql':
            kwargs.update({
                'poolclass': QueuePool,
                'pool_size': 20,
                'max_overflow': 30,
                'pool_pre_ping': True,
                'pool_recycle': 3600,
                'connect_args': {
                    'connect_timeout': 10,
                    'application_name': 'ChatAPI'
                }
            })
        elif self.database_type == 'mysql':
            kwargs.update({
                'poolclass': QueuePool,
                'pool_size': 10,
                'max_overflow': 20,
                'pool_pre_ping': True,
                'pool_recycle': 3600,
                'connect_args': {
                    'connect_timeout': 10,
                    'charset': 'utf8mb4'
                }
            })
        elif self.database_type == 'sqlite':
            kwargs.update({
                'poolclass': NullPool,
                'connect_args': {
                    'check_same_thread': False,
                    'timeout': 20
                }
            })
        elif self.database_type == 'mssql':
            kwargs.update({
                'poolclass': QueuePool,
                'pool_size': 10,
                'max_overflow': 20,
                'pool_pre_ping': True,
                'connect_args': {
                    'timeout': 10
                }
            })
        
        return kwargs
    
    def supports_feature(self, feature: str) -> bool:
        """Check if the database supports a specific feature."""
        return feature in self.config.get('features', [])


class DatabaseManager:
    """Enhanced database manager with advanced features."""
    
    def __init__(self, database_url: str):
        self.config = DatabaseConfig(database_url)
        self.engine = self._create_engine()
        self._setup_event_listeners()
        
        logger.info("Database manager initialized for %s", self.config.database_type)
    
    def _create_engine(self) -> Engine:
        """Create database engine with optimized configuration."""
        engine_kwargs = self.config.get_engine_kwargs()
        
        try:
            engine = create_engine(self.config.database_url, **engine_kwargs)
            
            # Test connection
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            logger.info("Database engine created successfully")
            return engine
            
        except Exception as e:
            logger.error("Failed to create database engine: %s", e)
            raise
    
    def _setup_event_listeners(self):
        """Setup database event listeners for monitoring and optimization."""
        
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            """Set SQLite pragmas for better performance."""
            if self.config.database_type == 'sqlite':
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA cache_size=10000")
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.close()
        
        @event.listens_for(self.engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            """Log connection checkout for monitoring."""
            logger.debug("Database connection checked out")
        
        @event.listens_for(self.engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record):
            """Log connection checkin for monitoring."""
            logger.debug("Database connection checked in")
    
    def create_tables(self, models: Optional[List[Type[SQLModel]]] = None):
        """Create database tables."""
        try:
            if models:
                # Create specific tables
                for model in models:
                    model.metadata.create_all(self.engine)
            else:
                # Create all tables
                SQLModel.metadata.create_all(self.engine)
            
            logger.info("Database tables created successfully")
            
        except Exception as e:
            logger.error("Failed to create database tables: %s", e)
            raise
    
    def drop_tables(self, models: Optional[List[Type[SQLModel]]] = None):
        """Drop database tables (use with caution)."""
        try:
            if models:
                # Drop specific tables
                for model in models:
                    model.metadata.drop_all(self.engine)
            else:
                # Drop all tables
                SQLModel.metadata.drop_all(self.engine)
            
            logger.warning("Database tables dropped")
            
        except Exception as e:
            logger.error("Failed to drop database tables: %s", e)
            raise
    
    def get_session(self):
        """Get database session generator for dependency injection."""
        with Session(self.engine) as session:
            try:
                yield session
            except Exception as e:
                session.rollback()
                logger.error("Database session error: %s", e)
                raise
            finally:
                session.close()
    
    def execute_raw_sql(self, sql: str, params: Optional[Dict] = None) -> Any:
        """Execute raw SQL query."""
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text(sql), params or {})
                conn.commit()
                return result
                
        except Exception as e:
            logger.error("Failed to execute raw SQL: %s", e)
            raise
    
    def get_database_info(self) -> Dict[str, Any]:
        """Get database information and statistics."""
        try:
            with self.engine.connect() as conn:
                info = {
                    'database_type': self.config.database_type,
                    'database_url': self._mask_credentials(self.config.database_url),
                    'features': self.config.config.get('features', []),
                    'pool_size': getattr(self.engine.pool, 'size', None),
                    'checked_out_connections': getattr(self.engine.pool, 'checkedout', None),
                    'overflow_connections': getattr(self.engine.pool, 'overflow', None),
                }
                
                # Database-specific information
                if self.config.database_type == 'postgresql':
                    result = conn.execute(text("SELECT version()"))
                    info['version'] = result.scalar()
                    
                    result = conn.execute(text("""
                        SELECT count(*) as active_connections 
                        FROM pg_stat_activity 
                        WHERE state = 'active'
                    """))
                    info['active_connections'] = result.scalar()
                    
                elif self.config.database_type == 'mysql':
                    result = conn.execute(text("SELECT VERSION()"))
                    info['version'] = result.scalar()
                    
                    result = conn.execute(text("SHOW STATUS LIKE 'Threads_connected'"))
                    row = result.fetchone()
                    info['active_connections'] = row[1] if row else None
                    
                elif self.config.database_type == 'sqlite':
                    result = conn.execute(text("SELECT sqlite_version()"))
                    info['version'] = result.scalar()
                    info['active_connections'] = 1  # SQLite is single-connection
                
                return info
                
        except Exception as e:
            logger.error("Failed to get database info: %s", e)
            return {'error': str(e)}
    
    def _mask_credentials(self, url: str) -> str:
        """Mask credentials in database URL for logging."""
        parsed = urlparse(url)
        if parsed.password:
            masked_url = url.replace(parsed.password, '***')
            return masked_url
        return url
    
    def test_connection(self) -> bool:
        """Test database connection."""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error("Database connection test failed: %s", e)
            return False
    
    def get_table_info(self) -> List[Dict[str, Any]]:
        """Get information about database tables."""
        try:
            with self.engine.connect() as conn:
                tables = []
                
                if self.config.database_type == 'postgresql':
                    result = conn.execute(text("""
                        SELECT 
                            table_name,
                            table_type,
                            (SELECT count(*) FROM information_schema.columns 
                             WHERE table_name = t.table_name) as column_count
                        FROM information_schema.tables t
                        WHERE table_schema = 'public'
                        ORDER BY table_name
                    """))
                    
                    for row in result:
                        tables.append({
                            'name': row[0],
                            'type': row[1],
                            'column_count': row[2]
                        })
                        
                elif self.config.database_type == 'mysql':
                    result = conn.execute(text("""
                        SELECT 
                            table_name,
                            table_type,
                            (SELECT count(*) FROM information_schema.columns 
                             WHERE table_name = t.table_name) as column_count
                        FROM information_schema.tables t
                        WHERE table_schema = DATABASE()
                        ORDER BY table_name
                    """))
                    
                    for row in result:
                        tables.append({
                            'name': row[0],
                            'type': row[1],
                            'column_count': row[2]
                        })
                        
                elif self.config.database_type == 'sqlite':
                    result = conn.execute(text("""
                        SELECT name, type FROM sqlite_master 
                        WHERE type IN ('table', 'view')
                        ORDER BY name
                    """))
                    
                    for row in result:
                        # Get column count for each table
                        col_result = conn.execute(text(f"PRAGMA table_info({row[0]})"))
                        column_count = len(col_result.fetchall())
                        
                        tables.append({
                            'name': row[0],
                            'type': row[1],
                            'column_count': column_count
                        })
                
                return tables
                
        except Exception as e:
            logger.error("Failed to get table info: %s", e)
            return []
    
    def optimize_database(self):
        """Perform database optimization tasks."""
        try:
            with self.engine.connect() as conn:
                if self.config.database_type == 'postgresql':
                    # Analyze tables for better query planning
                    conn.execute(text("ANALYZE"))
                    logger.info("PostgreSQL ANALYZE completed")
                    
                elif self.config.database_type == 'mysql':
                    # Optimize tables
                    tables = self.get_table_info()
                    for table in tables:
                        if table['type'] == 'BASE TABLE':
                            conn.execute(text(f"OPTIMIZE TABLE {table['name']}"))
                    logger.info("MySQL table optimization completed")
                    
                elif self.config.database_type == 'sqlite':
                    # Vacuum database
                    conn.execute(text("VACUUM"))
                    conn.execute(text("ANALYZE"))
                    logger.info("SQLite VACUUM and ANALYZE completed")
                    
        except Exception as e:
            logger.error("Database optimization failed: %s", e)
    
    def backup_database(self, backup_path: str) -> bool:
        """Create database backup (SQLite only for now)."""
        try:
            if self.config.database_type == 'sqlite':
                import shutil
                db_path = self.config.parsed_url.path
                shutil.copy2(db_path, backup_path)
                logger.info("SQLite database backed up to %s", backup_path)
                return True
            else:
                logger.warning("Backup not implemented for %s", self.config.database_type)
                return False
                
        except Exception as e:
            logger.error("Database backup failed: %s", e)
            return False
    
    def close(self):
        """Close database connections."""
        try:
            self.engine.dispose()
            logger.info("Database connections closed")
        except Exception as e:
            logger.error("Error closing database connections: %s", e)


# Global database manager instance
database_manager = DatabaseManager(settings.DATABASE_URL)
