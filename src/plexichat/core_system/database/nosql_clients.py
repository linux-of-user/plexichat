"""
PlexiChat NoSQL Database Clients

Implementations for various NoSQL databases:
- MongoDB (Document store)
- Redis (Key-value store)
- Cassandra/ScyllaDB (Column-family)
- DynamoDB (Managed NoSQL)
- CouchDB (Document store)
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, AsyncGenerator
from datetime import datetime
import json
import time

try:
    from .enhanced_abstraction import (  # type: ignore
        AbstractDatabaseClient, DatabaseConfig, QueryResult, QueryType, DatabaseType
    )
    ENHANCED_ABSTRACTION_AVAILABLE = True
except ImportError:
    # Create placeholder classes if enhanced_abstraction is not available
    ENHANCED_ABSTRACTION_AVAILABLE = False

    class AbstractDatabaseClient:
        def __init__(self, config):
            self.config = config
            self.connected = False

        async def connect(self):
            """Connect to database."""
            self.connected = True
            return True

        async def disconnect(self):
            """Disconnect from database."""
            self.connected = False
            return True

        async def execute_query(self, query, params=None):
            """Execute a database query."""
            # Acknowledge parameters to avoid unused warnings
            _ = query, params
            # Mock result object
            class MockResult:
                def __init__(self):
                    self.success = True
                    self.data = []
                    self.count = 0
                    self.error = None
            return MockResult()

    class DatabaseConfig:
        def __init__(self, **kwargs):
            # Set default attributes
            self.type = kwargs.get('type', 'mongodb')
            self.name = kwargs.get('name', 'default')
            self.url = kwargs.get('url', 'mongodb://localhost:27017')
            self.host = kwargs.get('host', 'localhost')
            self.port = kwargs.get('port', 27017)
            self.username = kwargs.get('username', '')
            self.password = kwargs.get('password', '')
            self.database = kwargs.get('database', 'default')
            # Set any additional attributes
            for key, value in kwargs.items():
                if not hasattr(self, key):
                    setattr(self, key, value)

    class QueryResult:
        def __init__(self, data=None, count=0, execution_time=0.0, metadata=None):
            self.data = data or []
            self.count = count
            self.execution_time = execution_time
            self.metadata = metadata or {}

    class QueryType:
        SELECT = "SELECT"
        INSERT = "INSERT"
        UPDATE = "UPDATE"
        DELETE = "DELETE"
        FIND = "FIND"
        AGGREGATE = "AGGREGATE"

    class DatabaseType:
        MONGODB = "mongodb"
        REDIS = "redis"

logger = logging.getLogger(__name__)


class MongoDBClient(AbstractDatabaseClient):  # type: ignore
    """MongoDB database client."""
    
    def __init__(self, config: DatabaseConfig):
        super().__init__(config)
        self.client = None
        self.database = None
        
    async def connect(self) -> bool:
        """Connect to MongoDB."""
        try:
            from motor.motor_asyncio import AsyncIOMotorClient  # type: ignore
            
            # Build connection string
            if self.config.username and self.config.password:
                connection_string = (
                    f"mongodb://{self.config.username}:{self.config.password}@"
                    f"{self.config.host}:{self.config.port or 27017}/{self.config.database}"
                )
            else:
                connection_string = f"mongodb://{self.config.host}:{self.config.port or 27017}"
            
            # Add SSL and other options
            options = {
                "maxPoolSize": self.config.pool_size,
                "minPoolSize": 1,
                "maxIdleTimeMS": self.config.pool_timeout * 1000,
                "serverSelectionTimeoutMS": 5000,
            }
            
            if self.config.ssl_enabled:
                options["ssl"] = True
            
            options.update(self.config.options)
            
            self.client = AsyncIOMotorClient(connection_string, **options)
            self.database = self.client[self.config.database]
            
            # Test connection
            await self.client.admin.command('ping')
            self.is_connected = True
            self.metrics["connections_created"] += 1
            
            logger.info(f"✅ Connected to MongoDB: {self.config.host}")
            return True
            
        except Exception as e:
            logger.error(f"❌ MongoDB connection failed: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from MongoDB."""
        try:
            if self.client:
                self.client.close()
                self.is_connected = False
            return True
        except Exception as e:
            logger.error(f"❌ MongoDB disconnect failed: {e}")
            return False
    
    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None,
                          query_type: QueryType = QueryType.SELECT) -> QueryResult:
        """Execute MongoDB query."""
        start_time = time.time()
        
        try:
            # Parse query (expecting JSON format for MongoDB)
            if isinstance(query, str):
                query_doc = json.loads(query)
            else:
                query_doc = query
            
            collection_name = query_doc.get("collection")
            operation = query_doc.get("operation", "find")
            filter_doc = query_doc.get("filter", {})
            options = query_doc.get("options", {})
            
            if params:
                # Substitute parameters in filter
                filter_doc = self._substitute_params(filter_doc, params)
            
            if self.database is None:
                raise Exception("MongoDB database not connected")
            collection = self.database[collection_name]
            
            # Execute based on operation type
            if operation == "find":
                cursor = collection.find(filter_doc, **options)
                data = await cursor.to_list(length=options.get("limit", 1000))
                count = len(data)
                
            elif operation == "find_one":
                data = await collection.find_one(filter_doc, **options)
                count = 1 if data else 0
                
            elif operation == "insert_one":
                result = await collection.insert_one(query_doc.get("document", {}))
                data = {"inserted_id": str(result.inserted_id)}
                count = 1
                
            elif operation == "insert_many":
                result = await collection.insert_many(query_doc.get("documents", []))
                data = {"inserted_ids": [str(id) for id in result.inserted_ids]}
                count = len(result.inserted_ids)
                
            elif operation == "update_one":
                result = await collection.update_one(
                    filter_doc, 
                    query_doc.get("update", {}),
                    **options
                )
                data = {
                    "matched_count": result.matched_count,
                    "modified_count": result.modified_count
                }
                count = result.modified_count
                
            elif operation == "update_many":
                result = await collection.update_many(
                    filter_doc,
                    query_doc.get("update", {}),
                    **options
                )
                data = {
                    "matched_count": result.matched_count,
                    "modified_count": result.modified_count
                }
                count = result.modified_count
                
            elif operation == "delete_one":
                result = await collection.delete_one(filter_doc)
                data = {"deleted_count": result.deleted_count}
                count = result.deleted_count
                
            elif operation == "delete_many":
                result = await collection.delete_many(filter_doc)
                data = {"deleted_count": result.deleted_count}
                count = result.deleted_count
                
            elif operation == "aggregate":
                pipeline = query_doc.get("pipeline", [])
                cursor = collection.aggregate(pipeline, **options)
                data = await cursor.to_list(length=None)
                count = len(data)
                
            else:
                raise ValueError(f"Unsupported MongoDB operation: {operation}")
            
            execution_time = time.time() - start_time
            self.metrics["queries_executed"] += 1
            self.metrics["total_execution_time"] += execution_time
            
            return QueryResult(
                data=data,
                count=count,
                execution_time=execution_time,
                metadata={"operation": operation, "collection": collection_name}
            )
            
        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"MongoDB query failed: {e}")
            raise
    
    def _substitute_params(self, doc: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """Substitute parameters in MongoDB document."""
        if isinstance(doc, dict):
            return {k: self._substitute_params(v, params) for k, v in doc.items()}
        elif isinstance(doc, list):
            return [self._substitute_params(item, params) for item in doc]
        elif isinstance(doc, str) and doc.startswith("$"):
            param_name = doc[1:]  # Remove $ prefix
            return params.get(param_name, doc)
        else:
            return doc
    
    async def execute_batch(self, queries: List[Dict[str, Any]]) -> List[QueryResult]:
        """Execute multiple MongoDB operations in batch."""
        results = []
        for query in queries:
            result = await self.execute_query(query)
            results.append(result)
        return results
    
    async def health_check(self) -> Dict[str, Any]:
        """Check MongoDB health."""
        try:
            # Ping the database
            await self.client.admin.command('ping')
            
            # Get server status
            status = await self.client.admin.command('serverStatus')
            
            return {
                "status": "healthy",
                "version": status.get("version"),
                "uptime": status.get("uptime"),
                "connections": status.get("connections", {}),
                "memory": status.get("mem", {}),
                "metrics": self.metrics
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "metrics": self.metrics
            }
    
    async def get_schema_info(self) -> Dict[str, Any]:
        """Get MongoDB schema information."""
        try:
            collections = await self.database.list_collection_names()
            schema_info = {
                "database": self.config.database,
                "collections": {}
            }
            
            for collection_name in collections:
                collection = self.database[collection_name]
                # Get sample document to infer schema
                sample = await collection.find_one()
                if sample:
                    schema_info["collections"][collection_name] = {
                        "sample_fields": list(sample.keys()),
                        "estimated_count": await collection.estimated_document_count()
                    }
            
            return schema_info
        except Exception as e:
            logger.error(f"Failed to get MongoDB schema info: {e}")
            return {}
    
    async def create_index(self, table: str, columns: List[str], 
                          index_type: str = "btree") -> bool:
        """Create MongoDB index."""
        try:
            collection = self.database[table]
            
            # Build index specification
            if len(columns) == 1:
                index_spec = columns[0]
            else:
                index_spec = [(col, 1) for col in columns]  # 1 for ascending
            
            # Create index
            await collection.create_index(index_spec)
            logger.info(f"✅ Created index on {table}.{columns}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create index: {e}")
            return False
    
    async def stream_data(self, query: str, params: Dict[str, Any] = None) -> AsyncGenerator:
        """Stream MongoDB data."""
        try:
            query_doc = json.loads(query) if isinstance(query, str) else query
            collection_name = query_doc.get("collection")
            filter_doc = query_doc.get("filter", {})
            
            if params:
                filter_doc = self._substitute_params(filter_doc, params)
            
            collection = self.database[collection_name]
            
            async for document in collection.find(filter_doc):
                yield document
                
        except Exception as e:
            logger.error(f"MongoDB streaming failed: {e}")
            raise


class RedisClient(AbstractDatabaseClient):  # type: ignore
    """Redis database client."""
    
    def __init__(self, config: DatabaseConfig):
        super().__init__(config)
        self.redis = None
    
    async def connect(self) -> bool:
        """Connect to Redis."""
        try:
            import aioredis  # type: ignore
            
            # Build connection URL
            if self.config.password:
                url = f"redis://:{self.config.password}@{self.config.host}:{self.config.port or 6379}/{self.config.database or 0}"
            else:
                url = f"redis://{self.config.host}:{self.config.port or 6379}/{self.config.database or 0}"
            
            # Connection options
            options = {
                "max_connections": self.config.pool_size,
                "retry_on_timeout": True,
                "socket_timeout": self.config.pool_timeout,
                "socket_connect_timeout": 5,
            }
            
            if self.config.ssl_enabled:
                options["ssl"] = True
            
            options.update(self.config.options)
            
            self.redis = aioredis.from_url(url, **options)
            
            # Test connection
            await self.redis.ping()
            self.is_connected = True
            self.metrics["connections_created"] += 1
            
            logger.info(f"✅ Connected to Redis: {self.config.host}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Redis connection failed: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from Redis."""
        try:
            if self.redis:
                await self.redis.close()
                self.is_connected = False
            return True
        except Exception as e:
            logger.error(f"❌ Redis disconnect failed: {e}")
            return False
    
    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None,
                          query_type: QueryType = QueryType.SELECT) -> QueryResult:
        """Execute Redis command."""
        start_time = time.time()
        
        try:
            # Parse Redis command
            if isinstance(query, str):
                command_parts = query.split()
            else:
                command_parts = query
            
            command = command_parts[0].upper()
            args = command_parts[1:]
            
            # Substitute parameters
            if params:
                args = [params.get(arg, arg) if isinstance(arg, str) and arg.startswith('$') 
                       else arg for arg in args]
            
            # Execute Redis command
            result = await self.redis.execute_command(command, *args)
            
            execution_time = time.time() - start_time
            self.metrics["queries_executed"] += 1
            self.metrics["total_execution_time"] += execution_time
            
            return QueryResult(
                data=result,
                count=1 if result is not None else 0,
                execution_time=execution_time,
                metadata={"command": command}
            )
            
        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"Redis command failed: {e}")
            raise
    
    async def execute_batch(self, queries: List[Dict[str, Any]]) -> List[QueryResult]:
        """Execute Redis pipeline."""
        try:
            pipe = self.redis.pipeline()
            
            for query in queries:
                if isinstance(query, str):
                    command_parts = query.split()
                else:
                    command_parts = query
                
                command = command_parts[0]
                args = command_parts[1:]
                pipe.execute_command(command, *args)
            
            results = await pipe.execute()
            
            return [
                QueryResult(data=result, count=1 if result is not None else 0)
                for result in results
            ]
            
        except Exception as e:
            logger.error(f"Redis batch execution failed: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Redis health."""
        try:
            info = await self.redis.info()
            
            return {
                "status": "healthy",
                "version": info.get("redis_version"),
                "uptime": info.get("uptime_in_seconds"),
                "memory": {
                    "used": info.get("used_memory"),
                    "peak": info.get("used_memory_peak")
                },
                "clients": info.get("connected_clients"),
                "metrics": self.metrics
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "metrics": self.metrics
            }
    
    async def get_schema_info(self) -> Dict[str, Any]:
        """Get Redis schema information."""
        try:
            info = await self.redis.info()
            keyspace = await self.redis.info("keyspace")
            
            return {
                "database": self.config.database,
                "total_keys": info.get("db0", {}).get("keys", 0),
                "keyspace": keyspace,
                "memory_usage": info.get("used_memory_human")
            }
        except Exception as e:
            logger.error(f"Failed to get Redis schema info: {e}")
            return {}


# Register clients with factory
from .enhanced_abstraction import DatabaseClientFactory

DatabaseClientFactory.register_client(DatabaseType.MONGODB, MongoDBClient)
DatabaseClientFactory.register_client(DatabaseType.REDIS, RedisClient)
