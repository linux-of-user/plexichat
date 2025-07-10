"""
PlexiChat Database Factory

Factory pattern implementation for creating appropriate database clients
based on configuration. Supports automatic client selection, connection
pooling, failover, and load balancing across multiple database types.
"""

import logging
from typing import Dict, Type, Optional, List, Any
from enum import Enum
import asyncio
from datetime import datetime, timezone

from .enhanced_abstraction import (
    AbstractDatabaseClient, DatabaseConfig, DatabaseType, 
    EnhancedDatabaseManager
)
from .sql_clients import PostgreSQLClient, MySQLClient, SQLiteClient
from .nosql_clients import MongoDBClient, RedisClient
from .analytics_clients import ClickHouseClient, TimescaleDBClient
from .lakehouse import MinIOLakehouseClient

logger = logging.getLogger(__name__)


class DatabaseClientFactory:
    """Factory for creating database clients based on configuration."""
    
    # Registry of available database client implementations
    _client_registry: Dict[DatabaseType, Type[AbstractDatabaseClient]] = {
        # SQL Databases
        DatabaseType.POSTGRESQL: PostgreSQLClient,
        DatabaseType.MYSQL: MySQLClient,
        DatabaseType.SQLITE: SQLiteClient,
        
        # NoSQL Databases
        DatabaseType.MONGODB: MongoDBClient,
        DatabaseType.REDIS: RedisClient,
        
        # Analytics Databases
        DatabaseType.CLICKHOUSE: ClickHouseClient,
        DatabaseType.TIMESCALEDB: TimescaleDBClient,
        
        # Lakehouse
        DatabaseType.MINIO: MinIOLakehouseClient,
    }
    
    @classmethod
    def register_client(cls, db_type: DatabaseType, client_class: Type[AbstractDatabaseClient]):
        """Register a new database client implementation."""
        cls._client_registry[db_type] = client_class
        logger.info(f"Registered database client: {db_type.value} -> {client_class.__name__}")
    
    @classmethod
    def create_client(cls, config: DatabaseConfig) -> AbstractDatabaseClient:
        """Create appropriate database client based on configuration."""
        if config.type not in cls._client_registry:
            raise ValueError(f"Unsupported database type: {config.type.value}")
        
        client_class = cls._client_registry[config.type]
        client = client_class(config)
        
        logger.info(f"Created {config.type.value} client: {config.name}")
        return client
    
    @classmethod
    def get_supported_types(cls) -> List[DatabaseType]:
        """Get list of supported database types."""
        return list(cls._client_registry.keys())
    
    @classmethod
    def is_supported(cls, db_type: DatabaseType) -> bool:
        """Check if database type is supported."""
        return db_type in cls._client_registry


class DatabaseManager:
    """Enhanced database manager with factory pattern and advanced features."""
    
    def __init__(self):
        self.clients: Dict[str, AbstractDatabaseClient] = {}
        self.configs: Dict[str, DatabaseConfig] = {}
        self.factory = DatabaseClientFactory()
        self.connection_status: Dict[str, bool] = {}
        self.health_check_interval = 30  # seconds
        self._health_check_task: Optional[asyncio.Task] = None
    
    async def add_database(self, name: str, config: DatabaseConfig) -> bool:
        """Add a database configuration and create client."""
        try:
            # Validate configuration
            if not self._validate_config(config):
                logger.error(f"Invalid configuration for database: {name}")
                return False
            
            # Create client using factory
            client = self.factory.create_client(config)
            
            # Store configuration and client
            self.configs[name] = config
            self.clients[name] = client
            self.connection_status[name] = False
            
            # Attempt to connect
            connected = await client.connect()
            self.connection_status[name] = connected
            
            if connected:
                logger.info(f"✅ Database '{name}' added and connected successfully")
            else:
                logger.warning(f"⚠️ Database '{name}' added but connection failed")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to add database '{name}': {e}")
            return False
    
    async def remove_database(self, name: str) -> bool:
        """Remove a database and disconnect."""
        try:
            if name in self.clients:
                client = self.clients[name]
                await client.disconnect()
                
                del self.clients[name]
                del self.configs[name]
                del self.connection_status[name]
                
                logger.info(f"✅ Database '{name}' removed successfully")
                return True
            else:
                logger.warning(f"⚠️ Database '{name}' not found")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to remove database '{name}': {e}")
            return False
    
    def get_client(self, name: str) -> Optional[AbstractDatabaseClient]:
        """Get database client by name."""
        return self.clients.get(name)
    
    def get_clients_by_type(self, db_type: DatabaseType) -> List[AbstractDatabaseClient]:
        """Get all clients of a specific database type."""
        return [
            client for name, client in self.clients.items()
            if self.configs[name].type == db_type
        ]
    
    async def connect_all(self) -> Dict[str, bool]:
        """Connect to all configured databases."""
        results = {}
        
        for name, client in self.clients.items():
            try:
                connected = await client.connect()
                self.connection_status[name] = connected
                results[name] = connected
                
                if connected:
                    logger.info(f"✅ Connected to database: {name}")
                else:
                    logger.error(f"❌ Failed to connect to database: {name}")
                    
            except Exception as e:
                logger.error(f"❌ Connection error for database '{name}': {e}")
                results[name] = False
                self.connection_status[name] = False
        
        return results
    
    async def disconnect_all(self) -> Dict[str, bool]:
        """Disconnect from all databases."""
        results = {}
        
        for name, client in self.clients.items():
            try:
                disconnected = await client.disconnect()
                self.connection_status[name] = False
                results[name] = disconnected
                
                if disconnected:
                    logger.info(f"✅ Disconnected from database: {name}")
                else:
                    logger.warning(f"⚠️ Disconnect issue for database: {name}")
                    
            except Exception as e:
                logger.error(f"❌ Disconnect error for database '{name}': {e}")
                results[name] = False
        
        return results
    
    async def health_check(self, name: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """Perform health check on databases."""
        results = {}
        
        databases_to_check = [name] if name else list(self.clients.keys())
        
        for db_name in databases_to_check:
            if db_name not in self.clients:
                results[db_name] = {
                    "status": "not_found",
                    "connected": False,
                    "error": "Database not configured"
                }
                continue
            
            client = self.clients[db_name]
            config = self.configs[db_name]
            
            try:
                # Simple health check query based on database type
                health_query = self._get_health_check_query(config.type)
                
                start_time = datetime.now(timezone.utc)
                result = await client.execute_query(health_query)
                response_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                
                if result.success:
                    results[db_name] = {
                        "status": "healthy",
                        "connected": True,
                        "response_time_ms": response_time,
                        "database_type": config.type.value
                    }
                    self.connection_status[db_name] = True
                else:
                    results[db_name] = {
                        "status": "unhealthy",
                        "connected": False,
                        "error": result.error,
                        "database_type": config.type.value
                    }
                    self.connection_status[db_name] = False
                    
            except Exception as e:
                results[db_name] = {
                    "status": "error",
                    "connected": False,
                    "error": str(e),
                    "database_type": config.type.value if db_name in self.configs else "unknown"
                }
                self.connection_status[db_name] = False
        
        return results
    
    def _get_health_check_query(self, db_type: DatabaseType) -> str:
        """Get appropriate health check query for database type."""
        health_queries = {
            DatabaseType.POSTGRESQL: "SELECT 1",
            DatabaseType.MYSQL: "SELECT 1",
            DatabaseType.SQLITE: "SELECT 1",
            DatabaseType.MONGODB: "db.runCommand({ping: 1})",
            DatabaseType.REDIS: "PING",
            DatabaseType.CLICKHOUSE: "SELECT 1",
            DatabaseType.TIMESCALEDB: "SELECT 1",
        }
        
        return health_queries.get(db_type, "SELECT 1")
    
    def _validate_config(self, config: DatabaseConfig) -> bool:
        """Validate database configuration."""
        if not config.type:
            logger.error("Database type is required")
            return False
        
        if not config.name:
            logger.error("Database name is required")
            return False
        
        # Check if database type is supported
        if not self.factory.is_supported(config.type):
            logger.error(f"Unsupported database type: {config.type.value}")
            return False
        
        # Type-specific validation
        if config.type in [DatabaseType.POSTGRESQL, DatabaseType.MYSQL]:
            if not all([config.host, config.port, config.username]):
                logger.error("Host, port, and username are required for SQL databases")
                return False
        
        elif config.type == DatabaseType.SQLITE:
            if not config.url:
                logger.error("URL is required for SQLite")
                return False
        
        return True
    
    async def start_health_monitoring(self):
        """Start background health monitoring."""
        if self._health_check_task and not self._health_check_task.done():
            logger.warning("Health monitoring already running")
            return
        
        self._health_check_task = asyncio.create_task(self._health_monitor_loop())
        logger.info("✅ Started database health monitoring")
    
    async def stop_health_monitoring(self):
        """Stop background health monitoring."""
        if self._health_check_task and not self._health_check_task.done():
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
            logger.info("✅ Stopped database health monitoring")
    
    async def _health_monitor_loop(self):
        """Background health monitoring loop."""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                
                health_results = await self.health_check()
                
                # Log any unhealthy databases
                for db_name, health in health_results.items():
                    if health["status"] != "healthy":
                        logger.warning(f"⚠️ Database '{db_name}' health check failed: {health.get('error', 'Unknown error')}")
                        
                        # Attempt to reconnect
                        if db_name in self.clients:
                            try:
                                client = self.clients[db_name]
                                await client.disconnect()
                                connected = await client.connect()
                                if connected:
                                    logger.info(f"✅ Reconnected to database: {db_name}")
                                    self.connection_status[db_name] = True
                            except Exception as e:
                                logger.error(f"❌ Failed to reconnect to database '{db_name}': {e}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Health monitoring error: {e}")
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get summary of all database statuses."""
        total_databases = len(self.clients)
        connected_databases = sum(1 for status in self.connection_status.values() if status)
        
        database_types = {}
        for name, config in self.configs.items():
            db_type = config.type.value
            if db_type not in database_types:
                database_types[db_type] = {"total": 0, "connected": 0}
            database_types[db_type]["total"] += 1
            if self.connection_status.get(name, False):
                database_types[db_type]["connected"] += 1
        
        return {
            "total_databases": total_databases,
            "connected_databases": connected_databases,
            "connection_rate": (connected_databases / total_databases * 100) if total_databases > 0 else 0,
            "database_types": database_types,
            "individual_status": dict(self.connection_status),
            "supported_types": [db_type.value for db_type in self.factory.get_supported_types()]
        }


# Global database manager instance
database_manager = DatabaseManager()
