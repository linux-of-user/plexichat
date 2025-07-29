"""
Enhanced Database Manager with Integrated Performance Optimizations

This module provides a high-performance database abstraction layer with:
- Integrated Redis caching for query results and metadata
- Advanced connection pooling with health monitoring
- Intelligent query optimization and rewriting
- Real-time performance monitoring and auto-tuning
- Distributed cache invalidation
- Connection multiplexing and load balancing
"""

import asyncio
import hashlib
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import threading
from collections import defaultdict, deque
import weakref

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool, QueuePool
from sqlalchemy import text, event
import sqlalchemy

from ..logging.unified_logging import get_logger
from .db_manager import ConsolidatedDatabaseManager, DatabaseConfig, DatabaseType, DatabaseRole, ConnectionStatus
from .performance_monitor import DatabasePerformanceMonitor
from .advanced_query_optimizer import QueryOptimizer

logger = get_logger(__name__)


class CacheLevel(Enum):
    """Cache level priorities."""
    L1_MEMORY = "l1_memory"      # In-process memory cache
    L2_REDIS = "l2_redis"        # Redis distributed cache
    L3_DATABASE = "l3_database"  # Database-level caching


@dataclass
class QueryCacheEntry:
    """Query cache entry with metadata."""
    result: Any
    cached_at: datetime
    expires_at: datetime
    query_hash: str
    table_names: List[str]
    cache_level: CacheLevel
    hit_count: int = 0
    last_accessed: datetime = field(default_factory=datetime.now)


@dataclass
class ConnectionPoolMetrics:
    """Enhanced connection pool metrics."""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    peak_connections: int = 0
    connection_errors: int = 0
    connection_timeouts: int = 0
    avg_connection_time_ms: float = 0.0
    pool_utilization_percent: float = 0.0
    connections_created: int = 0
    connections_destroyed: int = 0


class EnhancedConnectionPool:
    """Enhanced connection pool with health monitoring and load balancing."""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.engine: Optional[AsyncEngine] = None
        self.session_factory: Optional[sessionmaker] = None
        self.metrics = ConnectionPoolMetrics()
        
        # Health monitoring
        self.connection_health: Dict[str, bool] = {}
        self.last_health_check = datetime.now()
        self.health_check_interval = 30  # seconds
        
        # Load balancing
        self.connection_weights: Dict[str, float] = {}
        self.round_robin_counter = 0
        
        # Performance tracking
        self.query_times: deque = deque(maxlen=1000)
        self.error_rates: deque = deque(maxlen=100)
        
    async def initialize(self) -> bool:
        """Initialize the enhanced connection pool."""
        try:
            # Create connection string
            connection_string = self._build_connection_string()
            
            # Enhanced pool configuration
            pool_kwargs = {
                'pool_size': self.config.connection_pool_size,
                'max_overflow': self.config.max_overflow,
                'pool_timeout': self.config.pool_timeout,
                'pool_recycle': self.config.pool_recycle,
                'pool_pre_ping': True,  # Validate connections
                'pool_reset_on_return': 'commit',  # Reset state on return
            }
            
            # Use QueuePool for better performance
            if self.config.type in [DatabaseType.POSTGRESQL, DatabaseType.MYSQL, DatabaseType.MARIADB]:
                pool_kwargs['poolclass'] = QueuePool
            
            # Create async engine
            self.engine = create_async_engine(
                connection_string,
                **pool_kwargs,
                echo=False,  # Disable SQL logging for performance
                future=True,
                connect_args=self._get_connect_args()
            )
            
            # Create session factory
            self.session_factory = sessionmaker(
                bind=self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            # Set up event listeners for monitoring
            self._setup_event_listeners()
            
            # Test connection
            await self._test_connection()
            
            logger.info(f"Enhanced connection pool initialized for {self.config.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize connection pool for {self.config.name}: {e}")
            return False
    
    def _build_connection_string(self) -> str:
        """Build database connection string."""
        if self.config.type == DatabaseType.SQLITE:
            return f"sqlite+aiosqlite:///{self.config.database}"
        elif self.config.type == DatabaseType.POSTGRESQL:
            return f"postgresql+asyncpg://{self.config.username}:{self.config.password}@{self.config.host}:{self.config.port}/{self.config.database}"
        elif self.config.type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
            return f"mysql+aiomysql://{self.config.username}:{self.config.password}@{self.config.host}:{self.config.port}/{self.config.database}"
        else:
            raise ValueError(f"Unsupported database type: {self.config.type}")
    
    def _get_connect_args(self) -> Dict[str, Any]:
        """Get database-specific connection arguments."""
        args = {}
        
        if self.config.type == DatabaseType.POSTGRESQL:
            args.update({
                'server_settings': {
                    'application_name': 'plexichat',
                    'jit': 'off',  # Disable JIT for faster connection
                }
            })
        elif self.config.type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
            args.update({
                'charset': 'utf8mb4',
                'autocommit': False,
                'connect_timeout': 10,
            })
        elif self.config.type == DatabaseType.SQLITE:
            args.update({
                'check_same_thread': False,
                'timeout': 20,
            })
        
        return args
    
    def _setup_event_listeners(self):
        """Set up SQLAlchemy event listeners for monitoring."""
        if not self.engine:
            return
        
        @event.listens_for(self.engine.sync_engine, "connect")
        def on_connect(dbapi_connection, connection_record):
            self.metrics.connections_created += 1
            self.metrics.total_connections += 1
            self.metrics.peak_connections = max(
                self.metrics.peak_connections,
                self.metrics.total_connections
            )
        
        @event.listens_for(self.engine.sync_engine, "close")
        def on_close(dbapi_connection, connection_record):
            self.metrics.connections_destroyed += 1
            self.metrics.total_connections -= 1
        
        @event.listens_for(self.engine.sync_engine, "checkout")
        def on_checkout(dbapi_connection, connection_record, connection_proxy):
            self.metrics.active_connections += 1
            self.metrics.idle_connections = max(0, self.metrics.idle_connections - 1)
            self._update_pool_utilization()
        
        @event.listens_for(self.engine.sync_engine, "checkin")
        def on_checkin(dbapi_connection, connection_record):
            self.metrics.active_connections = max(0, self.metrics.active_connections - 1)
            self.metrics.idle_connections += 1
            self._update_pool_utilization()
    
    def _update_pool_utilization(self):
        """Update pool utilization metrics."""
        if self.config.connection_pool_size > 0:
            self.metrics.pool_utilization_percent = (
                self.metrics.active_connections / self.config.connection_pool_size * 100
            )
    
    async def _test_connection(self):
        """Test database connection."""
        async with self.session_factory() as session:
            if self.config.type == DatabaseType.SQLITE:
                result = await session.execute(text("SELECT 1"))
            elif self.config.type == DatabaseType.POSTGRESQL:
                result = await session.execute(text("SELECT version()"))
            elif self.config.type in [DatabaseType.MYSQL, DatabaseType.MARIADB]:
                result = await session.execute(text("SELECT VERSION()"))
            
            # Fetch the result properly
            row = result.fetchone()
            if row is None:
                raise RuntimeError("Connection test failed - no result returned")
    
    async def get_session(self) -> AsyncSession:
        """Get a database session."""
        if not self.session_factory:
            raise RuntimeError("Connection pool not initialized")
        
        return self.session_factory()
    
    async def execute_query(self, query: str, parameters: Optional[Dict] = None) -> Any:
        """Execute a query with performance tracking."""
        start_time = time.time()
        
        try:
            async with self.session_factory() as session:
                result = await session.execute(text(query), parameters or {})
                
                # Track performance
                execution_time = (time.time() - start_time) * 1000
                self.query_times.append(execution_time)
                self.metrics.avg_connection_time_ms = sum(self.query_times) / len(self.query_times)
                
                return result
                
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            self.error_rates.append(1)
            self.metrics.connection_errors += 1
            
            logger.error(f"Query execution failed: {e}")
            raise
    
    async def health_check(self) -> bool:
        """Perform connection health check."""
        try:
            await self._test_connection()
            return True
        except Exception as e:
            logger.warning(f"Health check failed for {self.config.name}: {e}")
            return False
    
    def get_metrics(self) -> ConnectionPoolMetrics:
        """Get current pool metrics."""
        return self.metrics
    
    async def close(self):
        """Close the connection pool."""
        if self.engine:
            await self.engine.dispose()
            logger.info(f"Connection pool closed for {self.config.name}")


class EnhancedQueryCache:
    """Multi-level query cache with Redis integration."""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client
        self.l1_cache: Dict[str, QueryCacheEntry] = {}  # In-memory cache
        self.cache_stats = {
            'l1_hits': 0,
            'l2_hits': 0,
            'misses': 0,
            'evictions': 0,
            'invalidations': 0
        }
        self.max_l1_size = 1000
        self._lock = threading.RLock()
        
        # Table dependency tracking for smart invalidation
        self.table_dependencies: Dict[str, set] = defaultdict(set)
    
    def _generate_cache_key(self, query: str, parameters: Optional[Dict] = None) -> str:
        """Generate cache key for query."""
        key_data = f"{query}:{json.dumps(parameters or {}, sort_keys=True)}"
        return f"query:{hashlib.sha256(key_data.encode()).hexdigest()}"
    
    def _extract_table_names(self, query: str) -> List[str]:
        """Extract table names from SQL query."""
        import re
        
        # Simple regex-based table extraction
        # This could be enhanced with a proper SQL parser
        tables = []
        
        # FROM clause
        from_match = re.search(r'from\s+(\w+)', query.lower())
        if from_match:
            tables.append(from_match.group(1))
        
        # JOIN clauses
        join_matches = re.findall(r'join\s+(\w+)', query.lower())
        tables.extend(join_matches)
        
        # INSERT INTO, UPDATE, DELETE FROM
        insert_match = re.search(r'insert\s+into\s+(\w+)', query.lower())
        if insert_match:
            tables.append(insert_match.group(1))
        
        update_match = re.search(r'update\s+(\w+)', query.lower())
        if update_match:
            tables.append(update_match.group(1))
        
        delete_match = re.search(r'delete\s+from\s+(\w+)', query.lower())
        if delete_match:
            tables.append(delete_match.group(1))
        
        return list(set(tables))
    
    async def get(self, query: str, parameters: Optional[Dict] = None) -> Optional[Any]:
        """Get cached query result."""
        cache_key = self._generate_cache_key(query, parameters)
        
        # Try L1 cache first
        with self._lock:
            if cache_key in self.l1_cache:
                entry = self.l1_cache[cache_key]
                
                # Check expiration
                if datetime.now() < entry.expires_at:
                    entry.hit_count += 1
                    entry.last_accessed = datetime.now()
                    self.cache_stats['l1_hits'] += 1
                    return entry.result
                else:
                    # Expired, remove from L1
                    del self.l1_cache[cache_key]
        
        # Try L2 cache (Redis)
        if self.redis_client:
            try:
                cached_data = await self.redis_client.get(cache_key)
                if cached_data:
                    entry_data = json.loads(cached_data)
                    
                    # Check expiration
                    expires_at = datetime.fromisoformat(entry_data['expires_at'])
                    if datetime.now() < expires_at:
                        self.cache_stats['l2_hits'] += 1
                        
                        # Promote to L1 cache
                        await self._promote_to_l1(cache_key, entry_data)
                        
                        return entry_data['result']
                    else:
                        # Expired, remove from Redis
                        await self.redis_client.delete(cache_key)
            except Exception as e:
                logger.warning(f"Redis cache get error: {e}")
        
        self.cache_stats['misses'] += 1
        return None
    
    async def set(self, query: str, result: Any, parameters: Optional[Dict] = None, 
                  ttl_seconds: int = 300) -> bool:
        """Cache query result."""
        cache_key = self._generate_cache_key(query, parameters)
        table_names = self._extract_table_names(query)
        
        expires_at = datetime.now() + timedelta(seconds=ttl_seconds)
        
        entry = QueryCacheEntry(
            result=result,
            cached_at=datetime.now(),
            expires_at=expires_at,
            query_hash=cache_key,
            table_names=table_names,
            cache_level=CacheLevel.L1_MEMORY
        )
        
        # Store in L1 cache
        with self._lock:
            # Evict if cache is full
            if len(self.l1_cache) >= self.max_l1_size:
                self._evict_lru()
            
            self.l1_cache[cache_key] = entry
            
            # Track table dependencies
            for table in table_names:
                self.table_dependencies[table].add(cache_key)
        
        # Store in L2 cache (Redis)
        if self.redis_client:
            try:
                entry_data = {
                    'result': result,
                    'cached_at': entry.cached_at.isoformat(),
                    'expires_at': entry.expires_at.isoformat(),
                    'table_names': table_names
                }
                
                await self.redis_client.setex(
                    cache_key,
                    ttl_seconds,
                    json.dumps(entry_data)
                )
                
                # Store table dependencies in Redis
                for table in table_names:
                    await self.redis_client.sadd(f"table_deps:{table}", cache_key)
                    await self.redis_client.expire(f"table_deps:{table}", ttl_seconds)
                    
            except Exception as e:
                logger.warning(f"Redis cache set error: {e}")
        
        return True
    
    async def _promote_to_l1(self, cache_key: str, entry_data: Dict):
        """Promote Redis cache entry to L1 cache."""
        with self._lock:
            if len(self.l1_cache) >= self.max_l1_size:
                self._evict_lru()
            
            entry = QueryCacheEntry(
                result=entry_data['result'],
                cached_at=datetime.fromisoformat(entry_data['cached_at']),
                expires_at=datetime.fromisoformat(entry_data['expires_at']),
                query_hash=cache_key,
                table_names=entry_data['table_names'],
                cache_level=CacheLevel.L1_MEMORY
            )
            
            self.l1_cache[cache_key] = entry
    
    def _evict_lru(self):
        """Evict least recently used entry from L1 cache."""
        if not self.l1_cache:
            return
        
        # Find LRU entry
        lru_key = min(
            self.l1_cache.keys(),
            key=lambda k: self.l1_cache[k].last_accessed
        )
        
        # Remove table dependencies
        entry = self.l1_cache[lru_key]
        for table in entry.table_names:
            self.table_dependencies[table].discard(lru_key)
        
        del self.l1_cache[lru_key]
        self.cache_stats['evictions'] += 1
    
    async def invalidate_table(self, table_name: str):
        """Invalidate all cached queries for a table."""
        # Invalidate L1 cache
        with self._lock:
            cache_keys_to_remove = list(self.table_dependencies[table_name])
            
            for cache_key in cache_keys_to_remove:
                if cache_key in self.l1_cache:
                    del self.l1_cache[cache_key]
                    self.cache_stats['invalidations'] += 1
            
            # Clear table dependencies
            self.table_dependencies[table_name].clear()
        
        # Invalidate L2 cache (Redis)
        if self.redis_client:
            try:
                # Get all cache keys for this table
                cache_keys = await self.redis_client.smembers(f"table_deps:{table_name}")
                
                if cache_keys:
                    # Delete cache entries
                    await self.redis_client.delete(*cache_keys)
                    
                    # Delete table dependency set
                    await self.redis_client.delete(f"table_deps:{table_name}")
                    
            except Exception as e:
                logger.warning(f"Redis cache invalidation error: {e}")
    
    async def clear(self):
        """Clear all caches."""
        with self._lock:
            self.l1_cache.clear()
            self.table_dependencies.clear()
        
        if self.redis_client:
            try:
                # Clear all query cache keys
                keys = await self.redis_client.keys("query:*")
                if keys:
                    await self.redis_client.delete(*keys)
                
                # Clear table dependency keys
                dep_keys = await self.redis_client.keys("table_deps:*")
                if dep_keys:
                    await self.redis_client.delete(*dep_keys)
                    
            except Exception as e:
                logger.warning(f"Redis cache clear error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = sum(self.cache_stats.values()) - self.cache_stats['evictions'] - self.cache_stats['invalidations']
        hit_rate = 0.0
        
        if total_requests > 0:
            total_hits = self.cache_stats['l1_hits'] + self.cache_stats['l2_hits']
            hit_rate = (total_hits / total_requests) * 100
        
        return {
            **self.cache_stats,
            'hit_rate_percent': hit_rate,
            'l1_cache_size': len(self.l1_cache),
            'l1_max_size': self.max_l1_size,
            'table_dependencies': len(self.table_dependencies)
        }


class EnhancedDatabaseManager(ConsolidatedDatabaseManager):
    """Enhanced database manager with integrated performance optimizations."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Enhanced components
        self.redis_client: Optional[redis.Redis] = None
        self.query_cache: Optional[EnhancedQueryCache] = None
        self.connection_pools: Dict[str, EnhancedConnectionPool] = {}
        self.query_optimizer = QueryOptimizer()
        self.performance_monitor = DatabasePerformanceMonitor(config)
        
        # Performance settings
        self.enable_query_cache = config.get('enable_query_cache', True) if config else True
        self.enable_query_optimization = config.get('enable_query_optimization', True) if config else True
        self.enable_performance_monitoring = config.get('enable_performance_monitoring', True) if config else True
        
        # Auto-tuning settings
        self.auto_tune_enabled = config.get('auto_tune_enabled', True) if config else True
        self.auto_tune_interval = config.get('auto_tune_interval', 300) if config else 300  # 5 minutes
        
        logger.info("Enhanced Database Manager initialized")
    
    async def initialize(self, config: Optional[Dict[str, Any]] = None) -> bool:
        """Initialize the enhanced database system."""
        try:
            # Initialize Redis connection
            await self._initialize_redis()
            
            # Initialize query cache
            self.query_cache = EnhancedQueryCache(self.redis_client)
            
            # Initialize performance monitoring
            if self.enable_performance_monitoring:
                await self.performance_monitor.start_monitoring()
            
            # Call parent initialization
            success = await super().initialize(config)
            
            if success and self.auto_tune_enabled:
                # Start auto-tuning task
                asyncio.create_task(self._auto_tune_loop())
            
            logger.info("Enhanced Database Manager fully initialized")
            return success
            
        except Exception as e:
            logger.error(f"Enhanced database manager initialization failed: {e}")
            return False
    
    async def _initialize_redis(self):
        """Initialize Redis connection for caching."""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, using in-memory cache only")
            return
        
        # Check if Redis is disabled in config
        redis_config = self.config.get('redis') if self.config else None
        if redis_config is None:
            logger.info("Redis disabled in configuration, using in-memory cache only")
            return
        
        try:
            self.redis_client = redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                password=redis_config.get('password'),
                db=redis_config.get('db', 0),
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30
            )
            
            # Test Redis connection
            await self.redis_client.ping()
            logger.info("Redis connection established for caching")
            
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}")
            self.redis_client = None
    
    async def add_database(self, name: str, config: DatabaseConfig, is_default: bool = False) -> bool:
        """Add database with enhanced connection pool."""
        try:
            # Create enhanced connection pool
            pool = EnhancedConnectionPool(config)
            
            if await pool.initialize():
                self.connection_pools[name] = pool
                self.database_configs[name] = config
                
                # Update parent class state
                self.connection_status[name] = ConnectionStatus.CONNECTED
                
                if is_default:
                    self.default_database = name
                
                logger.info(f"Enhanced database '{name}' added successfully")
                return True
            else:
                logger.error(f"Failed to initialize connection pool for '{name}'")
                return False
                
        except Exception as e:
            logger.error(f"Failed to add database '{name}': {e}")
            return False
    
    async def execute_query(self, query: str, parameters: Optional[Dict] = None, 
                          database: Optional[str] = None, use_cache: bool = True) -> Dict[str, Any]:
        """Execute query with caching and optimization."""
        start_time = time.time()
        database = database or self.default_database
        
        if not database or database not in self.connection_pools:
            return {
                "success": False,
                "error": f"Database '{database}' not found",
                "execution_time_ms": 0
            }
        
        try:
            # Generate query hash for caching
            query_hash = hashlib.sha256(f"{query}:{json.dumps(parameters or {}, sort_keys=True)}".encode()).hexdigest()
            
            # Try cache first (for SELECT queries)
            if use_cache and self.enable_query_cache and query.strip().lower().startswith('select'):
                cached_result = await self.query_cache.get(query, parameters)
                if cached_result is not None:
                    execution_time = (time.time() - start_time) * 1000
                    
                    # Record cache hit
                    if self.enable_performance_monitoring:
                        self.performance_monitor.record_query_execution(
                            query, execution_time / 1000, cache_hit=True
                        )
                    
                    return {
                        "success": True,
                        "result": cached_result,
                        "execution_time_ms": execution_time,
                        "cached": True
                    }
            
            # Optimize query if enabled
            optimized_query = query
            if self.enable_query_optimization:
                try:
                    optimization_result = await self.query_optimizer.optimize_query(query, parameters)
                    if optimization_result and optimization_result.optimized_query != query:
                        optimized_query = optimization_result.optimized_query
                        logger.debug(f"Query optimized: {len(optimization_result.optimizations_applied)} optimizations applied")
                except Exception as e:
                    logger.warning(f"Query optimization failed: {e}")
            
            # Execute query
            pool = self.connection_pools[database]
            result = await pool.execute_query(optimized_query, parameters)
            
            # Process result
            if hasattr(result, 'fetchall'):
                rows = result.fetchall()  # Remove await - fetchall is synchronous
                result_data = {
                    "rows": [dict(row._mapping) for row in rows],
                    "rowcount": len(rows)
                }
            else:
                result_data = {"rowcount": result.rowcount if hasattr(result, 'rowcount') else 0}
            
            execution_time = (time.time() - start_time) * 1000
            
            # Cache result for SELECT queries
            if (use_cache and self.enable_query_cache and 
                query.strip().lower().startswith('select') and 
                execution_time > 10):  # Only cache queries that take > 10ms
                
                await self.query_cache.set(query, result_data, parameters, ttl_seconds=300)
            
            # Record performance metrics
            if self.enable_performance_monitoring:
                self.performance_monitor.record_query_execution(
                    query, execution_time / 1000, 
                    rows_affected=result_data.get("rowcount", 0)
                )
            
            return {
                "success": True,
                "result": result_data,
                "execution_time_ms": execution_time,
                "cached": False,
                "optimized": optimized_query != query
            }
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            
            # Record error
            if self.enable_performance_monitoring:
                self.performance_monitor.record_query_execution(
                    query, execution_time / 1000, error=str(e)
                )
            
            logger.error(f"Query execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "execution_time_ms": execution_time
            }
    
    async def invalidate_cache_for_table(self, table_name: str):
        """Invalidate cache for all queries involving a table."""
        if self.query_cache:
            await self.query_cache.invalidate_table(table_name)
            logger.debug(f"Cache invalidated for table: {table_name}")
    
    async def _auto_tune_loop(self):
        """Auto-tuning loop for performance optimization."""
        while True:
            try:
                await asyncio.sleep(self.auto_tune_interval)
                await self._perform_auto_tuning()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Auto-tuning error: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _perform_auto_tuning(self):
        """Perform automatic performance tuning."""
        try:
            # Get performance summary
            perf_summary = self.performance_monitor.get_performance_summary()
            
            # Analyze connection pool utilization
            for name, pool in self.connection_pools.items():
                metrics = pool.get_metrics()
                
                # Auto-scale connection pool if needed
                if metrics.pool_utilization_percent > 80:
                    logger.info(f"High pool utilization detected for {name}: {metrics.pool_utilization_percent:.1f}%")
                    # Could implement dynamic pool scaling here
                
                # Check for connection errors
                if metrics.connection_errors > 10:
                    logger.warning(f"High connection error rate for {name}: {metrics.connection_errors}")
                    # Could implement connection pool reset here
            
            # Analyze cache performance
            if self.query_cache:
                cache_stats = self.query_cache.get_stats()
                
                if cache_stats['hit_rate_percent'] < 50:
                    logger.info(f"Low cache hit rate: {cache_stats['hit_rate_percent']:.1f}%")
                    # Could adjust cache TTL or size here
            
            logger.debug("Auto-tuning completed")
            
        except Exception as e:
            logger.error(f"Auto-tuning failed: {e}")
    
    async def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        stats = {
            "connection_pools": {},
            "query_cache": {},
            "performance_monitor": {},
            "redis_status": "connected" if self.redis_client else "disconnected"
        }
        
        # Connection pool stats
        for name, pool in self.connection_pools.items():
            stats["connection_pools"][name] = pool.get_metrics().__dict__
        
        # Cache stats
        if self.query_cache:
            stats["query_cache"] = self.query_cache.get_stats()
        
        # Performance monitor stats
        if self.enable_performance_monitoring:
            stats["performance_monitor"] = self.performance_monitor.get_performance_summary()
        
        return stats
    
    async def close(self):
        """Close all connections and cleanup."""
        try:
            # Close connection pools
            for pool in self.connection_pools.values():
                await pool.close()
            
            # Stop performance monitoring
            if self.enable_performance_monitoring:
                await self.performance_monitor.stop_monitoring()
            
            # Close Redis connection
            if self.redis_client:
                await self.redis_client.close()
            
            logger.info("Enhanced Database Manager closed")
            
        except Exception as e:
            logger.error(f"Error closing Enhanced Database Manager: {e}")


# Global enhanced database manager instance
_enhanced_db_manager: Optional[EnhancedDatabaseManager] = None


async def get_enhanced_db_manager(config: Optional[Dict[str, Any]] = None) -> EnhancedDatabaseManager:
    """Get or create the enhanced database manager instance."""
    global _enhanced_db_manager
    
    if _enhanced_db_manager is None:
        _enhanced_db_manager = EnhancedDatabaseManager(config)
        await _enhanced_db_manager.initialize()
    
    return _enhanced_db_manager


# Export main classes and functions
__all__ = [
    "EnhancedDatabaseManager",
    "EnhancedConnectionPool", 
    "EnhancedQueryCache",
    "ConnectionPoolMetrics",
    "QueryCacheEntry",
    "CacheLevel",
    "get_enhanced_db_manager"
]