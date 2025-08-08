import asyncio
import logging
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
import hashlib

logger = logging.getLogger(__name__)

# Import database abstraction layer
try:
    from plexichat.core.database import (  # type: ignore
        database_manager, execute_query, get_database_manager,
        DatabaseConfig, DatabaseType
    )
    DATABASE_AVAILABLE = True
except ImportError:
    database_manager = None
    execute_query = None
    get_database_manager = None
    DatabaseConfig = None
    DatabaseType = None
    DATABASE_AVAILABLE = False

# Import unified config system
try:
    from plexichat.core.unified_config import get_config  # type: ignore
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    def get_config(key: str, default: Any = None) -> Any:
        return default

# Import caching system - simplified fallbacks
CACHE_AVAILABLE = False
async def cache_get(key: str, default=None): 
    return default

async def cache_set(key: str, value, ttl=None): 
    return True

async def cache_delete(key: str): 
    return True

class CacheKeyBuilder:
    @staticmethod
    def user_key(user_id: str): 
        return f"user:{user_id}"
    
    @staticmethod
    def message_key(msg_id: str): 
        return f"message:{msg_id}"
    
    @staticmethod
    def session_key(session_id: str): 
        return f"session:{session_id}"


@dataclass
class QueryResult:
    """Database query result."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    rows_affected: int = 0
    execution_time: float = 0.0


class DatabaseService:
    """Simplified database service with caching and configuration integration."""
    
    def __init__(self):
        self.db_manager = None
        self.cache_enabled = CACHE_AVAILABLE
        self.config = None
        self.connection_pool = None
        self.query_cache = {}
        self.stats = {
            "queries_executed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "errors": 0
        }
        
    async def initialize(self):
        """Initialize the database service using unified configuration."""
        try:
            # Get configuration
            config = get_config("database") if CONFIG_AVAILABLE else None
            
            if DATABASE_AVAILABLE and database_manager:
                self.db_manager = database_manager
                
                # Configure database manager with unified config if available
                if config:
                    await self._configure_from_unified_config(config)
                    
            logger.info("Database service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database service: {e}")
            raise
    
    async def _configure_from_unified_config(self, config):
        """Configure database from unified config."""
        try:
            # Apply database configuration
            if hasattr(config, 'connection_string'):
                await self.db_manager.configure(connection_string=config.connection_string)
            
            # Configure caching if available
            if hasattr(config, 'cache_enabled'):
                self.cache_enabled = config.cache_enabled
                
        except Exception as e:
            logger.error(f"Failed to configure from unified config: {e}")
    
    async def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None,
                          cache_key: Optional[str] = None, cache_ttl: int = 300) -> QueryResult:
        """Execute a database query with optional caching."""
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Check cache first if enabled and cache_key provided
            if self.cache_enabled and cache_key:
                cached_result = await cache_get(cache_key)
                if cached_result is not None:
                    self.stats["cache_hits"] += 1
                    return QueryResult(
                        success=True,
                        data=cached_result,
                        execution_time=asyncio.get_event_loop().time() - start_time
                    )
                else:
                    self.stats["cache_misses"] += 1
            
            # Execute query
            if DATABASE_AVAILABLE and self.db_manager:
                result = await execute_query(query, params or {})
                data = result if result is not None else []
            else:
                # Fallback for when database is not available
                data = []
                logger.warning("Database not available, returning empty result")
            
            # Cache result if caching is enabled
            if self.cache_enabled and cache_key and data:
                await cache_set(cache_key, data, cache_ttl)
            
            self.stats["queries_executed"] += 1
            execution_time = asyncio.get_event_loop().time() - start_time
            
            return QueryResult(
                success=True,
                data=data,
                rows_affected=len(data) if isinstance(data, list) else 1,
                execution_time=execution_time
            )
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Query execution failed: {e}")
            return QueryResult(
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID with caching."""
        cache_key = CacheKeyBuilder.user_key(user_id)
        
        result = await self.execute_query(
            "SELECT * FROM users WHERE id = :user_id",
            {"user_id": user_id},
            cache_key=cache_key
        )
        
        if result.success and result.data:
            return result.data[0] if isinstance(result.data, list) else result.data
        return None
    
    async def create_user(self, user_data: Dict[str, Any]) -> QueryResult:
        """Create a new user."""
        query = """
        INSERT INTO users (id, username, email, created_at)
        VALUES (:id, :username, :email, :created_at)
        """
        
        result = await self.execute_query(query, user_data)
        
        # Invalidate user cache if creation was successful
        if result.success and "id" in user_data:
            cache_key = CacheKeyBuilder.user_key(user_data["id"])
            await cache_delete(cache_key)
        
        return result
    
    async def update_user(self, user_id: str, updates: Dict[str, Any]) -> QueryResult:
        """Update user data."""
        # Build dynamic update query
        set_clauses = [f"{key} = :{key}" for key in updates.keys()]
        query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = :user_id"
        
        params = {**updates, "user_id": user_id}
        result = await self.execute_query(query, params)
        
        # Invalidate user cache if update was successful
        if result.success:
            cache_key = CacheKeyBuilder.user_key(user_id)
            await cache_delete(cache_key)
        
        return result
    
    async def delete_user(self, user_id: str) -> QueryResult:
        """Delete a user."""
        result = await self.execute_query(
            "DELETE FROM users WHERE id = :user_id",
            {"user_id": user_id}
        )
        
        # Invalidate user cache if deletion was successful
        if result.success:
            cache_key = CacheKeyBuilder.user_key(user_id)
            await cache_delete(cache_key)
        
        return result
    
    async def search_users(self, search_term: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search users by username or email."""
        query = """
        SELECT * FROM users 
        WHERE username LIKE :search OR email LIKE :search
        LIMIT :limit
        """
        
        search_pattern = f"%{search_term}%"
        result = await self.execute_query(
            query,
            {"search": search_pattern, "limit": limit}
        )
        
        return result.data if result.success and result.data else []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database service statistics."""
        return {
            **self.stats,
            "cache_enabled": self.cache_enabled,
            "database_available": DATABASE_AVAILABLE,
            "config_available": CONFIG_AVAILABLE
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform a health check on the database service."""
        try:
            # Simple query to test database connectivity
            result = await self.execute_query("SELECT 1 as health_check")
            
            return {
                "status": "healthy" if result.success else "unhealthy",
                "database_available": DATABASE_AVAILABLE,
                "cache_available": CACHE_AVAILABLE,
                "last_error": result.error if not result.success else None,
                "stats": self.get_stats()
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "database_available": DATABASE_AVAILABLE,
                "cache_available": CACHE_AVAILABLE
            }
    
    async def cleanup(self):
        """Cleanup database service resources."""
        try:
            if self.db_manager and hasattr(self.db_manager, 'close'):
                await self.db_manager.close()
            
            self.query_cache.clear()
            logger.info("Database service cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during database service cleanup: {e}")


# Global database service instance
_database_service: Optional[DatabaseService] = None


def get_database_service() -> DatabaseService:
    """Get the global database service instance."""
    global _database_service
    if _database_service is None:
        _database_service = DatabaseService()
    return _database_service


async def initialize_database_service() -> DatabaseService:
    """Initialize and return the database service."""
    service = get_database_service()
    await service.initialize()
    return service
