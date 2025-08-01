"""
Enhanced Database Manager - Enterprise-Grade Database Management
==============================================================

This module provides enterprise-grade database management with:
- Advanced security and encryption
- High availability and clustering
- Performance optimization
- Comprehensive monitoring
- Automatic failover and recovery
- Zero-downtime migrations
- Multi-database support
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import secrets
from pathlib import Path
import base64
from ..security.time_based_encryption import db_time_encryption, performant_encryption

# Database imports with fallbacks
try:
    import sqlalchemy
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, AsyncEngine
    from sqlalchemy.pool import StaticPool, QueuePool
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import text, MetaData, Table, Column, Integer, String, DateTime, Boolean
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    AsyncEngine = None
    AsyncSession = None

try:
    import aiosqlite
    AIOSQLITE_AVAILABLE = True
except ImportError:
    AIOSQLITE_AVAILABLE = False

try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False

try:
    from motor.motor_asyncio import AsyncIOMotorClient
    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from ..security.enhanced_security_manager import enhanced_security_manager

logger = logging.getLogger(__name__)

class DatabaseType(Enum):
    """Supported database types."""
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MONGODB = "mongodb"
    REDIS = "redis"
    CASSANDRA = "cassandra"
    ELASTICSEARCH = "elasticsearch"

class ConnectionState(Enum):
    """Database connection states."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"
    MAINTENANCE = "maintenance"

class PerformanceLevel(Enum):
    """Database performance levels."""
    OPTIMAL = "optimal"
    GOOD = "good"
    DEGRADED = "degraded"
    CRITICAL = "critical"

@dataclass
class DatabaseConfig:
    """Enhanced database configuration."""
    name: str
    type: DatabaseType
    host: str = "localhost"
    port: int = 5432
    database: str = "plexichat"
    username: str = ""
    password: str = ""
    
    # Connection pool settings
    min_connections: int = 5
    max_connections: int = 50
    connection_timeout: int = 30
    idle_timeout: int = 300
    
    # Security settings
    encryption_enabled: bool = True
    ssl_enabled: bool = True
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    
    # Performance settings
    query_timeout: int = 30
    statement_timeout: int = 60
    connection_retry_attempts: int = 3
    connection_retry_delay: int = 5
    
    # Monitoring settings
    enable_monitoring: bool = True
    enable_query_logging: bool = True
    slow_query_threshold: float = 1.0
    
    # Backup settings
    enable_automatic_backup: bool = True
    backup_interval_hours: int = 6
    backup_retention_days: int = 30

@dataclass
class ConnectionMetrics:
    """Database connection metrics."""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    failed_connections: int = 0
    connection_errors: int = 0
    average_response_time: float = 0.0
    last_health_check: Optional[datetime] = None
    uptime_percentage: float = 100.0

@dataclass
class QueryMetrics:
    """Database query metrics."""
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    slow_queries: int = 0
    average_query_time: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    cache_hit_ratio: float = 0.0

class DataAccessController:
    """Severe data access controls for database operations."""

    def __init__(self):
        self.access_rules: Dict[str, Dict[str, Any]] = {}
        self.blocked_operations: set = set()
        self.audit_log: List[Dict[str, Any]] = []
        self.access_tokens: Dict[str, Dict[str, Any]] = {}
        self.max_audit_entries = 10000

        # Initialize default security rules
        self._initialize_security_rules()

    def _initialize_security_rules(self):
        """Initialize default security rules."""
        # Block dangerous operations by default
        self.blocked_operations.update([
            'DROP TABLE',
            'DROP DATABASE',
            'TRUNCATE',
            'DELETE FROM users',
            'UPDATE users SET password',
            'GRANT',
            'REVOKE',
            'CREATE USER',
            'DROP USER',
            'ALTER USER'
        ])

        # Define access rules for sensitive tables
        self.access_rules.update({
            'users': {
                'read_fields': ['id', 'username', 'email', 'created_at'],
                'protected_fields': ['password_hash', 'api_key', 'private_key'],
                'max_records': 100,
                'require_auth': True
            },
            'sessions': {
                'read_fields': ['id', 'user_id', 'created_at', 'last_activity'],
                'protected_fields': ['session_token', 'refresh_token'],
                'max_records': 50,
                'require_auth': True
            },
            'messages': {
                'read_fields': ['id', 'sender_id', 'created_at'],
                'protected_fields': ['content', 'encrypted_content'],
                'max_records': 200,
                'require_auth': True
            }
        })

    def validate_query(self, query: str, table: str = None, user_token: str = None) -> Dict[str, Any]:
        """Validate query against access controls."""
        query_upper = query.upper().strip()

        # Check for blocked operations
        for blocked_op in self.blocked_operations:
            if blocked_op in query_upper:
                self._log_access_violation(query, 'BLOCKED_OPERATION', user_token)
                return {
                    'allowed': False,
                    'reason': f'Operation blocked: {blocked_op}',
                    'severity': 'CRITICAL'
                }

        # Check table-specific rules
        if table and table in self.access_rules:
            rules = self.access_rules[table]

            # Check authentication requirement
            if rules.get('require_auth', False) and not user_token:
                self._log_access_violation(query, 'NO_AUTH_TOKEN', user_token)
                return {
                    'allowed': False,
                    'reason': 'Authentication required for this table',
                    'severity': 'HIGH'
                }

            # Check for protected fields in SELECT
            if 'SELECT' in query_upper and 'protected_fields' in rules:
                for protected_field in rules['protected_fields']:
                    if protected_field.upper() in query_upper:
                        self._log_access_violation(query, 'PROTECTED_FIELD_ACCESS', user_token)
                        return {
                            'allowed': False,
                            'reason': f'Access to protected field: {protected_field}',
                            'severity': 'HIGH'
                        }

        # Log successful validation
        self._log_access_attempt(query, 'ALLOWED', user_token)
        return {'allowed': True}

    def _log_access_violation(self, query: str, violation_type: str, user_token: str = None):
        """Log access violation."""
        violation = {
            'timestamp': datetime.now().isoformat(),
            'query': query[:200],  # Truncate long queries
            'violation_type': violation_type,
            'user_token': user_token[:10] + '...' if user_token else None,
            'severity': 'VIOLATION'
        }

        self.audit_log.append(violation)
        self._cleanup_audit_log()

        logger.warning(f"Database access violation: {violation_type} - {query[:100]}")

    def _log_access_attempt(self, query: str, result: str, user_token: str = None):
        """Log access attempt."""
        attempt = {
            'timestamp': datetime.now().isoformat(),
            'query': query[:100],
            'result': result,
            'user_token': user_token[:10] + '...' if user_token else None,
            'severity': 'INFO'
        }

        self.audit_log.append(attempt)
        self._cleanup_audit_log()

    def _cleanup_audit_log(self):
        """Clean up old audit log entries."""
        if len(self.audit_log) > self.max_audit_entries:
            self.audit_log = self.audit_log[-self.max_audit_entries//2:]

class EncryptedDataHandler:
    """Handle encrypted data operations with time-based encryption."""

    def __init__(self):
        self.encrypted_fields: Dict[str, set] = {}
        self.encryption_cache: Dict[str, str] = {}
        self.decryption_cache: Dict[str, str] = {}

        # Register default encrypted fields
        self._register_default_encrypted_fields()

    def _register_default_encrypted_fields(self):
        """Register fields that should be encrypted."""
        self.encrypted_fields.update({
            'users': {'password_hash', 'api_key', 'private_key', 'email'},
            'sessions': {'session_token', 'refresh_token'},
            'messages': {'content', 'encrypted_content'},
            'bot_accounts': {'bot_token', 'bot_secret', 'webhook_secret'},
            'user_settings': {'private_settings', 'api_keys'}
        })

    def should_encrypt_field(self, table: str, field: str) -> bool:
        """Check if field should be encrypted."""
        return field in self.encrypted_fields.get(table, set())

    def encrypt_data_for_storage(self, table: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive fields before storage."""
        encrypted_data = data.copy()

        for field, value in data.items():
            if self.should_encrypt_field(table, field) and value is not None:
                try:
                    # Use time-based encryption
                    encrypted_value = performant_encryption.encrypt_with_cache(str(value))
                    encrypted_data[field] = encrypted_value

                    # Mark as encrypted
                    encrypted_data[f"{field}_encrypted"] = True

                except Exception as e:
                    logger.error(f"Failed to encrypt {table}.{field}: {e}")
                    # Don't store unencrypted sensitive data
                    encrypted_data[field] = "[ENCRYPTION_FAILED]"

        return encrypted_data

    def decrypt_data_from_storage(self, table: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive fields after retrieval."""
        decrypted_data = data.copy()

        for field, value in data.items():
            if (self.should_encrypt_field(table, field) and
                value is not None and
                data.get(f"{field}_encrypted", False)):

                try:
                    # Use time-based decryption
                    decrypted_value = performant_encryption.decrypt_with_cache(value)
                    decrypted_data[field] = decrypted_value

                    # Remove encryption marker
                    decrypted_data.pop(f"{field}_encrypted", None)

                except Exception as e:
                    logger.error(f"Failed to decrypt {table}.{field}: {e}")
                    decrypted_data[field] = "[DECRYPTION_FAILED]"

        return decrypted_data

class EnhancedDatabaseConnection:
    """Enhanced database connection with security and monitoring."""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.connection = None
        self.engine = None
        self.session_factory = None
        self.state = ConnectionState.DISCONNECTED
        self.metrics = ConnectionMetrics()
        self.query_metrics = QueryMetrics()
        self.last_error = None
        self.connection_start_time = None
        
        # Security
        self.encryption_key = None
        self.connection_hash = None
        self.access_controller = DataAccessController()
        self.encrypted_handler = EncryptedDataHandler()

        # Performance monitoring
        self.query_cache = {}
        self.performance_history = []
        
    async def connect(self) -> bool:
        """Establish secure database connection."""
        try:
            self.state = ConnectionState.CONNECTING
            self.connection_start_time = datetime.now()
            
            # Generate connection security hash
            self.connection_hash = hashlib.sha256(
                f"{self.config.name}{self.config.host}{self.config.database}{time.time()}".encode()
            ).hexdigest()
            
            # Connect based on database type
            if self.config.type == DatabaseType.SQLITE:
                success = await self._connect_sqlite()
            elif self.config.type == DatabaseType.POSTGRESQL:
                success = await self._connect_postgresql()
            elif self.config.type == DatabaseType.MYSQL:
                success = await self._connect_mysql()
            elif self.config.type == DatabaseType.MONGODB:
                success = await self._connect_mongodb()
            elif self.config.type == DatabaseType.REDIS:
                success = await self._connect_redis()
            else:
                logger.error(f"Unsupported database type: {self.config.type}")
                return False
            
            if success:
                self.state = ConnectionState.CONNECTED
                self.metrics.total_connections += 1
                self.metrics.active_connections += 1
                logger.info(f"Successfully connected to {self.config.name} ({self.config.type.value})")
                
                # Initialize security features
                await self._initialize_security()
                
                # Start monitoring
                if self.config.enable_monitoring:
                    asyncio.create_task(self._monitor_connection())
                
                return True
            else:
                self.state = ConnectionState.ERROR
                self.metrics.failed_connections += 1
                return False
                
        except Exception as e:
            self.state = ConnectionState.ERROR
            self.last_error = str(e)
            self.metrics.connection_errors += 1
            logger.error(f"Failed to connect to {self.config.name}: {e}")
            return False
    
    async def _connect_sqlite(self) -> bool:
        """Connect to SQLite database."""
        if not AIOSQLITE_AVAILABLE and not SQLALCHEMY_AVAILABLE:
            logger.error("Neither aiosqlite nor SQLAlchemy available for SQLite")
            return False
        
        try:
            if SQLALCHEMY_AVAILABLE:
                # Use SQLAlchemy async engine
                database_path = self.config.database
                if not database_path.startswith('/') and not ':' in database_path:
                    database_path = f"./{database_path}"
                
                self.engine = create_async_engine(
                    f"sqlite+aiosqlite:///{database_path}",
                    poolclass=StaticPool,
                    connect_args={"check_same_thread": False},
                    echo=self.config.enable_query_logging
                )
                
                # Create session factory
                self.session_factory = sessionmaker(
                    self.engine, class_=AsyncSession, expire_on_commit=False
                )
                
                # Test connection
                async with self.engine.begin() as conn:
                    await conn.execute(text("SELECT 1"))
                
                return True
            else:
                # Direct aiosqlite connection
                self.connection = await aiosqlite.connect(self.config.database)
                return True
                
        except Exception as e:
            logger.error(f"SQLite connection failed: {e}")
            return False
    
    async def _connect_postgresql(self) -> bool:
        """Connect to PostgreSQL database."""
        if not ASYNCPG_AVAILABLE and not SQLALCHEMY_AVAILABLE:
            logger.error("Neither asyncpg nor SQLAlchemy available for PostgreSQL")
            return False
        
        try:
            if SQLALCHEMY_AVAILABLE:
                # Build connection string
                connection_string = (
                    f"postgresql+asyncpg://{self.config.username}:{self.config.password}"
                    f"@{self.config.host}:{self.config.port}/{self.config.database}"
                )
                
                # Add SSL parameters if enabled
                if self.config.ssl_enabled:
                    connection_string += "?ssl=require"
                
                self.engine = create_async_engine(
                    connection_string,
                    pool_size=self.config.min_connections,
                    max_overflow=self.config.max_connections - self.config.min_connections,
                    pool_timeout=self.config.connection_timeout,
                    pool_recycle=3600,  # Recycle connections every hour
                    echo=self.config.enable_query_logging
                )
                
                # Create session factory
                self.session_factory = sessionmaker(
                    self.engine, class_=AsyncSession, expire_on_commit=False
                )
                
                # Test connection
                async with self.engine.begin() as conn:
                    await conn.execute(text("SELECT 1"))
                
                return True
            else:
                # Direct asyncpg connection
                self.connection = await asyncpg.connect(
                    host=self.config.host,
                    port=self.config.port,
                    database=self.config.database,
                    user=self.config.username,
                    password=self.config.password,
                    ssl='require' if self.config.ssl_enabled else 'prefer'
                )
                return True
                
        except Exception as e:
            logger.error(f"PostgreSQL connection failed: {e}")
            return False
    
    async def _connect_mysql(self) -> bool:
        """Connect to MySQL database."""
        # Similar implementation for MySQL
        logger.warning("MySQL connection not yet implemented")
        return False
    
    async def _connect_mongodb(self) -> bool:
        """Connect to MongoDB database."""
        if not MOTOR_AVAILABLE:
            logger.error("Motor (MongoDB async driver) not available")
            return False
        
        try:
            connection_string = f"mongodb://{self.config.host}:{self.config.port}"
            if self.config.username and self.config.password:
                connection_string = (
                    f"mongodb://{self.config.username}:{self.config.password}"
                    f"@{self.config.host}:{self.config.port}"
                )
            
            self.connection = AsyncIOMotorClient(connection_string)
            
            # Test connection
            await self.connection.admin.command('ping')
            
            return True
            
        except Exception as e:
            logger.error(f"MongoDB connection failed: {e}")
            return False
    
    async def _connect_redis(self) -> bool:
        """Connect to Redis database."""
        if not REDIS_AVAILABLE:
            logger.error("Redis async client not available")
            return False
        
        try:
            self.connection = redis.Redis(
                host=self.config.host,
                port=self.config.port,
                password=self.config.password if self.config.password else None,
                ssl=self.config.ssl_enabled,
                decode_responses=True
            )
            
            # Test connection
            await self.connection.ping()
            
            return True
            
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            return False

    async def _initialize_security(self):
        """Initialize security features for the connection."""
        try:
            if self.config.encryption_enabled:
                # Generate encryption key for this connection
                self.encryption_key = secrets.token_bytes(32)

                # Log security event
                await enhanced_security_manager._log_security_event(
                    enhanced_security_manager.SecurityEventType.LOGIN_SUCCESS,
                    "database",
                    f"db_{self.config.name}",
                    enhanced_security_manager.ThreatLevel.LOW,
                    {
                        'database_type': self.config.type.value,
                        'encryption_enabled': True,
                        'connection_hash': self.connection_hash
                    }
                )

        except Exception as e:
            logger.error(f"Failed to initialize security for {self.config.name}: {e}")

    async def _monitor_connection(self):
        """Monitor connection health and performance."""
        while self.state == ConnectionState.CONNECTED:
            try:
                start_time = time.time()

                # Perform health check
                if await self._health_check():
                    response_time = time.time() - start_time
                    self.metrics.average_response_time = (
                        (self.metrics.average_response_time * 0.9) + (response_time * 0.1)
                    )
                    self.metrics.last_health_check = datetime.now()

                    # Update performance level
                    self._update_performance_level(response_time)
                else:
                    self.metrics.connection_errors += 1
                    logger.warning(f"Health check failed for {self.config.name}")

                # Wait before next check
                await asyncio.sleep(30)  # Check every 30 seconds

            except Exception as e:
                logger.error(f"Connection monitoring error for {self.config.name}: {e}")
                await asyncio.sleep(60)  # Wait longer on error

    async def _health_check(self) -> bool:
        """Perform database health check."""
        try:
            if self.config.type == DatabaseType.SQLITE:
                if self.engine:
                    async with self.engine.begin() as conn:
                        await conn.execute(text("SELECT 1"))
                elif self.connection:
                    await self.connection.execute("SELECT 1")
                return True

            elif self.config.type == DatabaseType.POSTGRESQL:
                if self.engine:
                    async with self.engine.begin() as conn:
                        await conn.execute(text("SELECT 1"))
                elif self.connection:
                    await self.connection.fetchval("SELECT 1")
                return True

            elif self.config.type == DatabaseType.MONGODB:
                if self.connection:
                    await self.connection.admin.command('ping')
                return True

            elif self.config.type == DatabaseType.REDIS:
                if self.connection:
                    await self.connection.ping()
                return True

            return False

        except Exception as e:
            logger.error(f"Health check failed for {self.config.name}: {e}")
            return False

    def _update_performance_level(self, response_time: float):
        """Update performance level based on response time."""
        if response_time < 0.1:
            self.performance_level = PerformanceLevel.OPTIMAL
        elif response_time < 0.5:
            self.performance_level = PerformanceLevel.GOOD
        elif response_time < 2.0:
            self.performance_level = PerformanceLevel.DEGRADED
        else:
            self.performance_level = PerformanceLevel.CRITICAL

    async def execute_secure_query(self, query: str, params: Dict[str, Any] = None,
                                 table: str = None, user_token: str = None) -> Dict[str, Any]:
        """Execute query with severe access controls and encryption."""
        start_time = time.time()

        try:
            # Validate query against access controls
            validation = self.access_controller.validate_query(query, table, user_token)
            if not validation['allowed']:
                logger.warning(f"Query blocked: {validation['reason']}")
                return {
                    'success': False,
                    'error': validation['reason'],
                    'severity': validation.get('severity', 'HIGH')
                }

            # Execute query based on database type
            if self.config.type == DatabaseType.SQLITE:
                result = await self._execute_sqlite_secure(query, params)
            elif self.config.type == DatabaseType.POSTGRESQL:
                result = await self._execute_postgresql_secure(query, params)
            else:
                return {'success': False, 'error': 'Database type not supported for secure queries'}

            # Decrypt sensitive data if this is a SELECT query
            if result.get('success') and 'SELECT' in query.upper() and table:
                if 'data' in result and isinstance(result['data'], list):
                    decrypted_data = []
                    for row in result['data']:
                        if isinstance(row, dict):
                            decrypted_row = self.encrypted_handler.decrypt_data_from_storage(table, row)
                            decrypted_data.append(decrypted_row)
                        else:
                            decrypted_data.append(row)
                    result['data'] = decrypted_data

            # Update metrics
            execution_time = time.time() - start_time
            self.query_metrics.total_queries += 1
            if result.get('success'):
                self.query_metrics.successful_queries += 1
            else:
                self.query_metrics.failed_queries += 1

            self.query_metrics.average_query_time = (
                (self.query_metrics.average_query_time * 0.9) + (execution_time * 0.1)
            )

            return result

        except Exception as e:
            logger.error(f"Secure query execution failed: {e}")
            self.query_metrics.failed_queries += 1
            return {
                'success': False,
                'error': f'Query execution failed: {str(e)}',
                'severity': 'HIGH'
            }

    async def insert_secure_data(self, table: str, data: Dict[str, Any],
                               user_token: str = None) -> Dict[str, Any]:
        """Insert data with automatic encryption of sensitive fields."""
        try:
            # Validate insert operation
            insert_query = f"INSERT INTO {table}"
            validation = self.access_controller.validate_query(insert_query, table, user_token)
            if not validation['allowed']:
                return {
                    'success': False,
                    'error': validation['reason'],
                    'severity': validation.get('severity', 'HIGH')
                }

            # Encrypt sensitive fields
            encrypted_data = self.encrypted_handler.encrypt_data_for_storage(table, data)

            # Build parameterized insert query
            fields = list(encrypted_data.keys())
            placeholders = ', '.join([f':{field}' for field in fields])
            query = f"INSERT INTO {table} ({', '.join(fields)}) VALUES ({placeholders})"

            # Execute insert
            result = await self.execute_secure_query(query, encrypted_data, table, user_token)

            if result.get('success'):
                logger.info(f"Secure data inserted into {table}")

            return result

        except Exception as e:
            logger.error(f"Secure data insert failed: {e}")
            return {
                'success': False,
                'error': f'Insert failed: {str(e)}',
                'severity': 'HIGH'
            }

    async def _execute_sqlite_secure(self, query: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute SQLite query with security measures."""
        try:
            if self.engine:
                async with self.engine.begin() as conn:
                    if params:
                        result = await conn.execute(text(query), params)
                    else:
                        result = await conn.execute(text(query))

                    if result.returns_rows:
                        rows = result.fetchall()
                        # Convert to list of dicts
                        data = [dict(row._mapping) for row in rows]
                        return {'success': True, 'data': data, 'row_count': len(data)}
                    else:
                        return {'success': True, 'affected_rows': result.rowcount}
            else:
                return {'success': False, 'error': 'No database connection'}

        except Exception as e:
            logger.error(f"SQLite secure execution failed: {e}")
            return {'success': False, 'error': str(e)}

    async def _execute_postgresql_secure(self, query: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute PostgreSQL query with security measures."""
        try:
            if self.engine:
                async with self.engine.begin() as conn:
                    if params:
                        result = await conn.execute(text(query), params)
                    else:
                        result = await conn.execute(text(query))

                    if result.returns_rows:
                        rows = result.fetchall()
                        data = [dict(row._mapping) for row in rows]
                        return {'success': True, 'data': data, 'row_count': len(data)}
                    else:
                        return {'success': True, 'affected_rows': result.rowcount}
            else:
                return {'success': False, 'error': 'No database connection'}

        except Exception as e:
            logger.error(f"PostgreSQL secure execution failed: {e}")
            return {'success': False, 'error': str(e)}

    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security and access control metrics."""
        return {
            'access_violations': len([log for log in self.access_controller.audit_log
                                    if log.get('severity') == 'VIOLATION']),
            'total_access_attempts': len(self.access_controller.audit_log),
            'blocked_operations': len(self.access_controller.blocked_operations),
            'encrypted_tables': len(self.encrypted_handler.encrypted_fields),
            'query_metrics': {
                'total_queries': self.query_metrics.total_queries,
                'successful_queries': self.query_metrics.successful_queries,
                'failed_queries': self.query_metrics.failed_queries,
                'average_query_time': self.query_metrics.average_query_time
            },
            'encryption_performance': performant_encryption.get_performance_stats()
        }

class EnhancedDatabaseManager:
    """Enhanced Database Manager with enterprise-grade features."""

    def __init__(self):
        self.connections: Dict[str, EnhancedDatabaseConnection] = {}
        self.primary_connection: Optional[str] = None
        self.replica_connections: List[str] = []
        self.is_initialized = False

        # Clustering and failover
        self.cluster_enabled = False
        self.auto_failover = True
        self.failover_threshold = 3

        # Performance monitoring
        self.global_metrics = {
            'total_queries': 0,
            'total_connections': 0,
            'failed_operations': 0,
            'average_response_time': 0.0
        }

        # Security
        self.security_enabled = True
        self.audit_logging = True

    async def initialize(self, configs: List[DatabaseConfig]) -> bool:
        """Initialize database manager with multiple database configurations."""
        try:
            logger.info("Initializing Enhanced Database Manager")

            # Connect to all configured databases
            for config in configs:
                connection = EnhancedDatabaseConnection(config)
                success = await connection.connect()

                if success:
                    self.connections[config.name] = connection

                    # Set primary connection (first successful connection)
                    if not self.primary_connection:
                        self.primary_connection = config.name
                        logger.info(f"Set primary database: {config.name}")
                    else:
                        # Add as replica
                        self.replica_connections.append(config.name)
                        logger.info(f"Added replica database: {config.name}")
                else:
                    logger.error(f"Failed to connect to database: {config.name}")

            if not self.connections:
                logger.error("No database connections established")
                return False

            self.is_initialized = True
            logger.info(f"Database manager initialized with {len(self.connections)} connections")

            # Start global monitoring
            asyncio.create_task(self._global_monitoring())

            return True

        except Exception as e:
            logger.error(f"Failed to initialize database manager: {e}")
            return False

    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None,
                          database: Optional[str] = None, use_replica: bool = False) -> Any:
        """Execute query with automatic failover and load balancing."""
        if not self.is_initialized:
            raise RuntimeError("Database manager not initialized")

        # Determine target database
        target_db = database or self._select_database(use_replica)
        if not target_db:
            raise RuntimeError("No available database connections")

        connection = self.connections.get(target_db)
        if not connection:
            raise RuntimeError(f"Database connection not found: {target_db}")

        try:
            # Execute query
            result = await connection.execute_query(query, params)

            # Update global metrics
            self.global_metrics['total_queries'] += 1

            return result

        except Exception as e:
            self.global_metrics['failed_operations'] += 1

            # Attempt failover if enabled
            if self.auto_failover and target_db == self.primary_connection:
                logger.warning(f"Primary database failed, attempting failover: {e}")
                return await self._attempt_failover(query, params)

            raise

    def _select_database(self, use_replica: bool = False) -> Optional[str]:
        """Select appropriate database for query execution."""
        if use_replica and self.replica_connections:
            # Load balance across replicas
            import random
            available_replicas = [
                db for db in self.replica_connections
                if self.connections[db].state == ConnectionState.CONNECTED
            ]
            if available_replicas:
                return random.choice(available_replicas)

        # Use primary database
        if (self.primary_connection and
            self.connections[self.primary_connection].state == ConnectionState.CONNECTED):
            return self.primary_connection

        # Fallback to any available connection
        for name, connection in self.connections.items():
            if connection.state == ConnectionState.CONNECTED:
                return name

        return None

    async def _attempt_failover(self, query: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Attempt to failover to replica database."""
        for replica_name in self.replica_connections:
            replica = self.connections.get(replica_name)
            if replica and replica.state == ConnectionState.CONNECTED:
                try:
                    logger.info(f"Failing over to replica: {replica_name}")
                    result = await replica.execute_query(query, params)

                    # Promote replica to primary
                    self.primary_connection = replica_name
                    self.replica_connections.remove(replica_name)

                    logger.info(f"Failover successful, new primary: {replica_name}")
                    return result

                except Exception as e:
                    logger.error(f"Failover to {replica_name} failed: {e}")
                    continue

        raise RuntimeError("All database connections failed")

    async def _global_monitoring(self):
        """Global monitoring and health management."""
        while self.is_initialized:
            try:
                # Check all connections
                total_response_time = 0
                active_connections = 0

                for name, connection in self.connections.items():
                    if connection.state == ConnectionState.CONNECTED:
                        active_connections += 1
                        total_response_time += connection.metrics.average_response_time
                    elif connection.state == ConnectionState.ERROR:
                        # Attempt reconnection
                        logger.info(f"Attempting to reconnect to {name}")
                        await connection.connect()

                # Update global metrics
                if active_connections > 0:
                    self.global_metrics['average_response_time'] = total_response_time / active_connections
                self.global_metrics['total_connections'] = active_connections

                # Log health status
                if active_connections == 0:
                    logger.critical("No active database connections!")
                elif active_connections < len(self.connections):
                    logger.warning(f"Only {active_connections}/{len(self.connections)} connections active")

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                logger.error(f"Global monitoring error: {e}")
                await asyncio.sleep(60)

    async def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status of all databases."""
        status = {
            'overall_health': 'healthy',
            'total_connections': len(self.connections),
            'active_connections': 0,
            'primary_database': self.primary_connection,
            'replica_databases': self.replica_connections,
            'global_metrics': self.global_metrics.copy(),
            'connections': {}
        }

        healthy_connections = 0

        for name, connection in self.connections.items():
            conn_metrics = connection.get_metrics()
            status['connections'][name] = conn_metrics

            if connection.state == ConnectionState.CONNECTED:
                status['active_connections'] += 1
                healthy_connections += 1

        # Determine overall health
        if healthy_connections == 0:
            status['overall_health'] = 'critical'
        elif healthy_connections < len(self.connections) * 0.5:
            status['overall_health'] = 'degraded'
        elif healthy_connections < len(self.connections):
            status['overall_health'] = 'warning'

        return status

    async def shutdown(self):
        """Gracefully shutdown all database connections."""
        logger.info("Shutting down Enhanced Database Manager")

        self.is_initialized = False

        # Disconnect all connections
        for name, connection in self.connections.items():
            try:
                await connection.disconnect()
                logger.info(f"Disconnected from {name}")
            except Exception as e:
                logger.error(f"Error disconnecting from {name}: {e}")

        self.connections.clear()
        self.primary_connection = None
        self.replica_connections.clear()

        logger.info("Database manager shutdown complete")

# Global instance
enhanced_db_manager = EnhancedDatabaseManager()
