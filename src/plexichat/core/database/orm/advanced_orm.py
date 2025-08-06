import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar

from sqlmodel import Session, SQLModel, select


from sqlalchemy import MetaData, create_engine, event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload, sessionmaker
from sqlalchemy.pool import NullPool, QueuePool

"""
import time
PlexiChat Advanced ORM Layer
Enhanced SQLModel integration with advanced features and optimizations
"""

logger = logging.getLogger(__name__)

# Type variables
T = TypeVar("T", bound=SQLModel)


class ConnectionPoolType(Enum):
    """Database connection pool types."""
        QUEUE_POOL = "queue_pool"
    NULL_POOL = "null_pool"
    STATIC_POOL = "static_pool"
    ASYNC_POOL = "async_pool"


class IsolationLevel(Enum):
    """Transaction isolation levels."""

    READ_UNCOMMITTED = "READ_UNCOMMITTED"
    READ_COMMITTED = "READ_COMMITTED"
    REPEATABLE_READ = "REPEATABLE_READ"
    SERIALIZABLE = "SERIALIZABLE"


@dataclass
class ORMConfig:
    """ORM configuration.
        database_url: str
    async_database_url: Optional[str] = None
    pool_type: ConnectionPoolType = ConnectionPoolType.QUEUE_POOL
    pool_size: int = 20
    max_overflow: int = 30
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False
    echo_pool: bool = False
    isolation_level: IsolationLevel = IsolationLevel.READ_COMMITTED

    # Advanced features
    enable_lazy_loading: bool = True
    enable_query_cache: bool = True
    enable_connection_events: bool = True
    enable_performance_monitoring: bool = True

    # Security
    enable_sql_injection_protection: bool = True
    enable_query_logging: bool = True
    max_query_time: int = 30  # seconds


@dataclass
class QueryMetrics:
    """Query performance metrics."""
        query_count: int = 0
    total_execution_time: float = 0.0
    average_execution_time: float = 0.0
    slowest_query_time: float = 0.0
    fastest_query_time: float = float("inf")
    cache_hits: int = 0
    cache_misses: int = 0


class AdvancedORM:
    """
    Advanced ORM Layer with SQLModel Integration.

    Features:
    - Enhanced SQLModel integration
    - Advanced connection pooling
    - Query optimization and caching
    - Performance monitoring
    - Automatic relationship loading
    - Transaction management
    - Connection health monitoring
    - SQL injection protection
    """
        def __init__(self, config: ORMConfig):
        self.config = config
        self.sync_engine = None
        self.async_engine = None
        self.sync_session_factory = None
        self.async_session_factory = None
        self.metadata = MetaData()

        # Performance monitoring
        self.query_metrics = QueryMetrics()
        self.connection_metrics = {
            "active_connections": 0,
            "total_connections": 0,
            "failed_connections": 0,
            "connection_errors": [],
        }

        # Query cache
        self.query_cache: Dict[str, Any] = {}
        self.cache_ttl = 300  # 5 minutes
        self.cache_timestamps: Dict[str, datetime] = {}

        # Registered models
        self.registered_models: Dict[str, Type[SQLModel]] = {}

        # Event handlers
        self.event_handlers: Dict[str, List[Callable]] = {
            "before_connect": [],
            "after_connect": [],
            "before_query": [],
            "after_query": [],
            "query_error": [],
            "connection_error": [],
        }

    async def initialize(self):
        """Initialize ORM engines and sessions."""
        try:
            # Create sync engine
            self.sync_engine = self._create_sync_engine()

            # Create async engine if URL provided
            if self.config.async_database_url:
                self.async_engine = self._create_async_engine()

            # Create session factories
            self.sync_session_factory = sessionmaker()
                bind=self.sync_engine, class_=Session, expire_on_commit=False
            )

            if self.async_engine:
                self.async_session_factory = async_sessionmaker()
                    bind=self.async_engine, class_=AsyncSession, expire_on_commit=False
                )

            # Setup event listeners
            if self.config.enable_connection_events:
                self._setup_event_listeners()

            # Create tables
            await self._create_tables()

            logger.info(" Advanced ORM initialized successfully")

        except Exception as e:
            logger.error(f" Failed to initialize ORM: {e}")
            raise

    def _create_sync_engine(self):
        """Create synchronous SQLAlchemy engine."""
        pool_class = self._get_pool_class()

        engine_kwargs = {
            "url": self.config.database_url,
            "echo": self.config.echo,
            "echo_pool": self.config.echo_pool,
            "poolclass": pool_class,
            "isolation_level": self.config.isolation_level.value,
        }

        # Add pool configuration
        if pool_class != NullPool:
            engine_kwargs.update()
                {
                    "pool_size": self.config.pool_size,
                    "max_overflow": self.config.max_overflow,
                    "pool_timeout": self.config.pool_timeout,
                    "pool_recycle": self.config.pool_recycle,
                }
            )

        return create_engine(**engine_kwargs)

    def _create_async_engine(self):
        """Create asynchronous SQLAlchemy engine."""
        pool_class = self._get_pool_class()

        engine_kwargs = {
            "url": self.config.async_database_url,
            "echo": self.config.echo,
            "echo_pool": self.config.echo_pool,
            "poolclass": pool_class,
        }

        # Add pool configuration
        if pool_class != NullPool:
            engine_kwargs.update()
                {
                    "pool_size": self.config.pool_size,
                    "max_overflow": self.config.max_overflow,
                    "pool_timeout": self.config.pool_timeout,
                    "pool_recycle": self.config.pool_recycle,
                }
            )

        return create_async_engine(**engine_kwargs)

    def _get_pool_class(self):
        """Get SQLAlchemy pool class based on configuration.
        pool_mapping = {
            ConnectionPoolType.QUEUE_POOL: QueuePool,
            ConnectionPoolType.NULL_POOL: NullPool,
            ConnectionPoolType.STATIC_POOL: QueuePool,  # Fallback
            ConnectionPoolType.ASYNC_POOL: QueuePool,
        }
        return pool_mapping.get(self.config.pool_type, QueuePool)

    def _setup_event_listeners(self):
        """Setup SQLAlchemy event listeners for monitoring."""

        @event.listens_for(self.sync_engine, "connect")
        def on_connect(dbapi_connection, connection_record):
            self.connection_metrics["total_connections"] += 1
            self.connection_metrics["active_connections"] += 1
            self._trigger_event("after_connect", dbapi_connection)

        @event.listens_for(self.sync_engine, "close")
        def on_close(dbapi_connection, connection_record):
            self.connection_metrics["active_connections"] -= 1

        @event.listens_for(self.sync_engine, "before_cursor_execute")
        def on_before_execute():
            conn, cursor, statement, parameters, context, executemany
        ):
            context._query_start_time = datetime.now(timezone.utc)
            self._trigger_event("before_query", statement, parameters)

        @event.listens_for(self.sync_engine, "after_cursor_execute")
        def on_after_execute(conn, cursor, statement, parameters, context, executemany):
            if hasattr(context, "_query_start_time"):
                execution_time = (
                    datetime.now(timezone.utc) - context._query_start_time
                ).total_seconds()
                self._update_query_metrics(execution_time)
                self._trigger_event("after_query", statement, execution_time)

    async def _create_tables(self):
        """Create database tables for registered models.
        if self.async_engine:
            async with self.async_engine.begin() as conn:
                await conn.run_sync(SQLModel.metadata.create_all)
        else:
            if self.sync_engine is not None:
                SQLModel.metadata.create_all(self.sync_engine)

    # Session Management

    def get_sync_session(self) -> Session:
        """Get synchronous session."""
        if not self.sync_session_factory:
            raise RuntimeError("ORM not initialized")
        return self.sync_session_factory()

    async def get_async_session(self) -> AsyncSession:
        """Get asynchronous session."""
        if not self.async_session_factory:
            raise RuntimeError("Async ORM not initialized")
        return self.async_session_factory()

    async def execute_query(
        self,
        query: str,
        parameters: Optional[Dict[str, Any]] = None,
        use_cache: bool = True,
    ) -> Any:
        """Execute raw SQL query with caching and monitoring."""

        # Check cache first
        if use_cache and self.config.enable_query_cache:
            cache_key = self._get_cache_key(query, parameters or {})
            cached_result = self._get_from_cache(cache_key)
            if cached_result:
                self.query_metrics.cache_hits += 1
                return cached_result
            self.query_metrics.cache_misses += 1

        start_time = datetime.now(timezone.utc)

        try:
            # Execute query
            if self.async_session_factory:
                async with await self.get_async_session() as session:
                    result = await session.execute(text(query), parameters or {})
                    await session.commit()
                    data = result.fetchall()
            else:
                with self.get_sync_session() as session:
                    result = session.execute(text(query), parameters or {})
                    session.commit()
                    data = result.fetchall()

            # Update metrics
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            self._update_query_metrics(execution_time)

            # Cache result
            if use_cache and self.config.enable_query_cache:
                cache_key = self._get_cache_key(query, parameters or {})
                self._put_in_cache(cache_key, data)

            return data

        except Exception as e:
            self._trigger_event("query_error", query, str(e))
            logger.error(f"Query execution failed: {e}")
            raise

    # Model Registration and Management

    def register_model(self, model_class: Type[SQLModel], name: Optional[str] = None):
        """Register SQLModel class."""
        model_name = name or model_class.__name__
        self.registered_models[model_name] = model_class
        logger.debug(f"Registered model: {model_name}")

    def get_model(self, name: str) -> Optional[Type[SQLModel]]:
        """Get registered model by name.
        return self.registered_models.get(name)

    def list_models(self) -> List[str]:
        """List all registered model names."""
        return list(self.registered_models.keys())

    # Advanced Query Builder

    async def find_by_id(
        self,
        model_class: Type[T],
        id: Any,
        include_relations: Optional[List[str]] = None,
    ) -> Optional[T]:
        Find model instance by ID with optional relationship loading."""

        if self.async_session_factory:
            async with await self.get_async_session() as session:
                # Use getattr to safely access id attribute
                id_attr = getattr(model_class, "id", None)
                if id_attr is None:
                    raise ValueError(
                        f"Model {model_class.__name__} does not have an 'id' attribute"
                    )
                query = select(model_class).where(id_attr == id)

                # Add relationship loading efficiently
                if include_relations:
                    options = []
                    for relation in include_relations:
                        if hasattr(model_class, relation):
                            options.append(
                                selectinload(getattr(model_class, relation))
                            )
                    if options:
                        query = query.options(*options)

                result = await session.execute(query)
                return result.scalar_one_or_none()
        else:
            with self.get_sync_session() as session:
                # Use getattr to safely access id attribute
                id_attr = getattr(model_class, "id", None)
                if id_attr is None:
                    raise ValueError(
                        f"Model {model_class.__name__} does not have an 'id' attribute"
                    )
                query = select(model_class).where(id_attr == id)

                # Add relationship loading
                if include_relations:
                    for relation in include_relations:
                        if hasattr(model_class, relation):
                            query = query.options(
                                selectinload(getattr(model_class, relation))
                            )

                result = session.execute(query)
                return result.scalar_one_or_none()

    async def find_all()
        self,
        model_class: Type[T],
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        include_relations: Optional[List[str]] = None,
    ) -> List[T]:
        """Find all model instances with filtering and pagination."""

        query = select(model_class)

        # Apply filters
        if filters:
            for field, value in filters.items():
                if hasattr(model_class, field):
                    query = query.where(getattr(model_class, field) == value)

        # Apply ordering
        if order_by:
            for field in order_by:
                if field.startswith("-"):
                    # Descending order
                    field_name = field[1:]
                    if hasattr(model_class, field_name):
                        query = query.order_by(getattr(model_class, field_name).desc())
                else:
                    # Ascending order
                    if hasattr(model_class, field):
                        query = query.order_by(getattr(model_class, field))

        # Apply pagination
        if offset:
            query = query.offset(offset)
        if limit:
            query = query.limit(limit)

        # Add relationship loading
        if include_relations:
            for relation in include_relations:
                if hasattr(model_class, relation):
                    query = query.options(selectinload(getattr(model_class, relation)))

        # Execute query
        if self.async_session_factory:
            async with await self.get_async_session() as session:
                result = await session.execute(query)
                return list(result.scalars().all())
        else:
            with self.get_sync_session() as session:
                result = session.execute(query)
                return list(result.scalars().all())

    async def create(self, model_instance: T) -> T:
        """Create new model instance.

        if self.async_session_factory:
            async with await self.get_async_session() as session:
                session.add(model_instance)
                await session.commit()
                await session.refresh(model_instance)
                return model_instance
        else:
            with self.get_sync_session() as session:
                session.add(model_instance)
                session.commit()
                session.refresh(model_instance)
                return model_instance

    async def update(self, model_instance: T) -> T:
        """Update existing model instance."""

        if self.async_session_factory:
            async with await self.get_async_session() as session:
                session.add(model_instance)
                await session.commit()
                await session.refresh(model_instance)
                return model_instance
        else:
            with self.get_sync_session() as session:
                session.add(model_instance)
                session.commit()
                session.refresh(model_instance)
                return model_instance

    async def delete(self, model_instance: SQLModel) -> bool:
        Delete model instance."""

        try:
            if self.async_session_factory:
                async with await self.get_async_session() as session:
                    await session.delete(model_instance)
                    await session.commit()
            else:
                with self.get_sync_session() as session:
                    session.delete(model_instance)
                    session.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to delete model instance: {e}")
            return False

    # Caching Methods

    def _get_cache_key():
        self, query: str, parameters: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate cache key for query."""
        content = f"{query}:{parameters or {}}"
        return hashlib.md5(content.encode()).hexdigest()

    def _get_from_cache(self, key: str) -> Any:
        """Get result from cache.
        if key not in self.query_cache:
            return None

        # Check TTL
        if key in self.cache_timestamps:
            age = ()
                datetime.now(timezone.utc) - self.cache_timestamps[key]
            ).total_seconds()
            if age > self.cache_ttl:
                self._remove_from_cache(key)
                return None

        return self.query_cache[key]

    def _put_in_cache(self, key: str, data: Any):
        """Put result in cache."""
        self.query_cache[key] = data
        self.cache_timestamps[key] = datetime.now(timezone.utc)

    def _remove_from_cache(self, key: str):
        Remove result from cache."""
        self.query_cache.pop(key, None)
        self.cache_timestamps.pop(key, None)

    def clear_cache(self):
        """Clear query cache.
        self.query_cache.clear()
        self.cache_timestamps.clear()

    # Metrics and Monitoring

    def _update_query_metrics(self, execution_time: float):
        """Update query performance metrics."""
        self.query_metrics.query_count += 1
        self.query_metrics.total_execution_time += execution_time
        self.query_metrics.average_execution_time = ()
            self.query_metrics.total_execution_time / self.query_metrics.query_count
        )

        if execution_time > self.query_metrics.slowest_query_time:
            self.query_metrics.slowest_query_time = execution_time

        if execution_time < self.query_metrics.fastest_query_time:
            self.query_metrics.fastest_query_time = execution_time

    def _trigger_event(self, event_name: str, *args, **kwargs):
        Trigger event handlers."""
        if event_name in self.event_handlers:
            for handler in self.event_handlers[event_name]:
                try:
                    handler(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Event handler error for {event_name}: {e}")

    def add_event_handler(self, event_name: str, handler: Callable):
        """Add event handler.
        if event_name not in self.event_handlers:
            self.event_handlers[event_name] = []
        self.event_handlers[event_name].append(handler)

    def get_statistics(self) -> Dict[str, Any]:
        """Get ORM statistics."""
        cache_hit_rate = 0.0
        total_cache_operations = ()
            self.query_metrics.cache_hits + self.query_metrics.cache_misses
        )
        if total_cache_operations > 0:
            cache_hit_rate = self.query_metrics.cache_hits / total_cache_operations

        return {
            "query_metrics": {
                "query_count": self.query_metrics.query_count,
                "average_execution_time": self.query_metrics.average_execution_time,
                "slowest_query_time": self.query_metrics.slowest_query_time,
                "fastest_query_time": ()
                    self.query_metrics.fastest_query_time
                    if self.query_metrics.fastest_query_time != float("inf")
                    else 0.0
                ),
                "cache_hit_rate": cache_hit_rate,
            },
            "connection_metrics": self.connection_metrics,
            "registered_models": len(self.registered_models),
            "cache_size": len(self.query_cache),
            "configuration": {
                "pool_size": self.config.pool_size,
                "max_overflow": self.config.max_overflow,
                "pool_type": self.config.pool_type.value,
                "isolation_level": self.config.isolation_level.value,
            },
        }

    async def health_check(self) -> Dict[str, Any]:
        """Perform ORM health check."""
        try:
            start_time = datetime.now(timezone.utc)

            # Test database connection
            if self.async_session_factory:
                async with await self.get_async_session() as session:
                    await session.execute(select(1))
            else:
                with self.get_sync_session() as session:
                    session.execute(select(1))

            end_time = datetime.now(timezone.utc)
            response_time = (end_time - start_time).total_seconds() * 1000

            return {
                "status": "healthy",
                "response_time_ms": response_time,
                "active_connections": self.connection_metrics["active_connections"],
                "total_connections": self.connection_metrics["total_connections"],
                "last_check": end_time.isoformat(),
            }

        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "last_check": datetime.now(timezone.utc).isoformat(),
            }

    async def shutdown(self):
        """Shutdown ORM engines."""
        try:
            if self.async_engine:
                await self.async_engine.dispose()

            if self.sync_engine:
                self.sync_engine.dispose()

            logger.info(" ORM shutdown complete")

        except Exception as e:
            logger.error(f"Error during ORM shutdown: {e}")


# Global ORM instance
advanced_orm = AdvancedORM(ORMConfig(database_url="sqlite:///plexichat.db"))
