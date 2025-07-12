"""
PlexiChat Phase IV Database Abstraction Integration
Coordinates all Phase IV database enhancements into a unified system
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Type, TypeVar, Callable
from sqlmodel import SQLModel
from datetime import datetime, timezone
from dataclasses import dataclass

from ..dao.base_dao import BaseDAO, QueryOptions, FilterCriteria, SortCriteria, PaginationParams, FilterOperator
from ..repository.base_repository import BaseRepository, RepositoryConfig, CacheStrategy
from ..orm.advanced_orm import AdvancedORM, ORMConfig
from ..manager import ConsolidatedDatabaseManager, database_manager

logger = logging.getLogger(__name__)

T = TypeVar('T', bound=SQLModel)


@dataclass
class DatabaseMetrics:
    """Database system metrics."""
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    average_response_time: float = 0.0
    cache_hit_rate: float = 0.0
    active_connections: int = 0
    dao_operations: int = 0
    repository_operations: int = 0
    orm_operations: int = 0


class Phase4DatabaseCoordinator:
    """
    Phase IV Database Abstraction Coordinator.
    
    Integrates all Phase IV database enhancements:
    1. DAO (Data Access Object) Pattern
    2. Repository Pattern with Domain Logic
    3. Advanced ORM Layer (SQLModel)
    4. Query Builder and Optimization
    5. Database Connection Pooling
    6. Caching Strategies
    7. Transaction Management
    8. Performance Monitoring
    9. Database Health Monitoring
    10. Migration and Schema Management
    """
    
    def __init__(self):
        self.enabled = True
        self.components = {
            "dao_pattern": True,
            "repository_pattern": True,
            "advanced_orm": True,
            "query_optimization": True,
            "connection_pooling": True,
            "caching_strategies": True,
            "transaction_management": True,
            "performance_monitoring": True,
            "health_monitoring": True,
            "migration_management": True
        }
        
        # Component instances
        self.database_manager = database_manager
        self.advanced_orm: Optional[AdvancedORM] = None
        
        # Registered DAOs and Repositories
        self.registered_daos: Dict[str, BaseDAO] = {}
        self.registered_repositories: Dict[str, BaseRepository] = {}
        
        # Metrics and monitoring
        self.metrics = DatabaseMetrics()
        self.performance_history: List[Dict[str, Any]] = []
        
        # Configuration
        self.default_cache_strategy = CacheStrategy.READ_THROUGH
        self.default_cache_ttl = 300  # 5 minutes
        self.query_timeout = 30  # seconds
        self.connection_pool_size = 20
        
        # Statistics
        self.stats = {
            "initialization_time": None,
            "total_dao_instances": 0,
            "total_repository_instances": 0,
            "database_connections": 0,
            "cache_operations": 0,
            "transaction_count": 0,
            "migration_count": 0,
            "last_health_check": None
        }
    
    async def initialize(self):
        """Initialize all Phase IV database components."""
        if not self.enabled:
            return
        
        start_time = datetime.now(timezone.utc)
        logger.info("🗄️ Initializing Phase IV Database Abstraction System")
        
        try:
            # 1. Initialize Database Manager
            if self.components["connection_pooling"]:
                await self._initialize_database_manager()
            
            # 2. Initialize Advanced ORM
            if self.components["advanced_orm"]:
                await self._initialize_advanced_orm()
            
            # 3. Setup Performance Monitoring
            if self.components["performance_monitoring"]:
                await self._setup_performance_monitoring()
            
            # 4. Setup Health Monitoring
            if self.components["health_monitoring"]:
                await self._setup_health_monitoring()
            
            # 5. Initialize Migration Management
            if self.components["migration_management"]:
                await self._initialize_migration_management()
            
            # Start monitoring
            asyncio.create_task(self._database_monitoring_loop())
            
            initialization_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.stats["initialization_time"] = initialization_time
            
            logger.info(f"✅ Phase IV Database Abstraction System initialized in {initialization_time:.2f}s")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Phase IV database system: {e}")
            raise
    
    async def _initialize_database_manager(self):
        """Initialize consolidated database manager."""
        # Database manager should already be initialized
        # We'll just verify it's working
        status = self.database_manager.get_status()
        if status["initialized"]:
            logger.info("✅ Database Manager verified")
        else:
            logger.warning("⚠️ Database Manager not initialized")
    
    async def _initialize_advanced_orm(self):
        """Initialize advanced ORM layer."""
        # Create ORM configuration
        orm_config = ORMConfig(
            database_url="sqlite:///plexichat.db",  # Default, should be configurable
            pool_size=self.connection_pool_size,
            enable_query_cache=True,
            enable_performance_monitoring=True
        )
        
        # Initialize ORM
        self.advanced_orm = AdvancedORM(orm_config)
        await self.advanced_orm.initialize()
        
        logger.info("✅ Advanced ORM initialized")
    
    async def _setup_performance_monitoring(self):
        """Setup database performance monitoring."""
        # Performance monitoring is integrated into individual components
        logger.info("✅ Performance Monitoring configured")
    
    async def _setup_health_monitoring(self):
        """Setup database health monitoring."""
        # Health monitoring will be performed in the monitoring loop
        logger.info("✅ Health Monitoring configured")
    
    async def _initialize_migration_management(self):
        """Initialize migration management."""
        # Migration management is part of the database manager
        logger.info("✅ Migration Management ready")
    
    # DAO Management
    
    def register_dao(self, name: str, dao: BaseDAO):
        """Register a DAO instance."""
        self.registered_daos[name] = dao
        self.stats["total_dao_instances"] = len(self.registered_daos)
        logger.debug(f"Registered DAO: {name}")
    
    def get_dao(self, name: str) -> Optional[BaseDAO]:
        """Get registered DAO by name."""
        return self.registered_daos.get(name)
    
    def list_daos(self) -> List[str]:
        """List all registered DAO names."""
        return list(self.registered_daos.keys())
    
    # Repository Management
    
    def register_repository(self, name: str, repository: BaseRepository):
        """Register a repository instance."""
        self.registered_repositories[name] = repository
        self.stats["total_repository_instances"] = len(self.registered_repositories)
        logger.debug(f"Registered Repository: {name}")
    
    def get_repository(self, name: str) -> Optional[BaseRepository]:
        """Get registered repository by name."""
        return self.registered_repositories.get(name)
    
    def list_repositories(self) -> List[str]:
        """List all registered repository names."""
        return list(self.registered_repositories.keys())
    
    # Factory Methods
    
    def create_dao(self, model_class: Type[T], name: Optional[str] = None) -> BaseDAO:
        """Create and register a new DAO instance."""
        dao_name = name or f"{model_class.__name__}DAO"
        
        # Create session factory
        session_factory = self._create_session_factory()
        
        # Create DAO instance
        dao = BaseDAO(model_class, session_factory)
        
        # Register DAO
        self.register_dao(dao_name, dao)
        
        return dao
    
    def create_repository(self,
                         dao: BaseDAO,
                         name: Optional[str] = None,
                         config: Optional[RepositoryConfig] = None) -> BaseRepository:
        """Create and register a new repository instance."""
        repo_name = name or f"{dao.model_class.__name__}Repository"
        
        # Use default config if not provided
        if config is None:
            config = RepositoryConfig(
                cache_strategy=self.default_cache_strategy,
                cache_ttl=self.default_cache_ttl
            )
        
        # Create repository instance (this would be a concrete implementation)
        # For now, we'll create a generic repository
        repository = self._create_generic_repository(dao, config)
        
        # Register repository
        self.register_repository(repo_name, repository)
        
        return repository
    
    def _create_session_factory(self):
        """Create database session factory."""
        if self.advanced_orm:
            return self.advanced_orm.get_async_session
        else:
            # Fallback to database cluster session
            from ..engines import db_cluster
            return db_cluster.get_session
    
    def _create_generic_repository(self, dao: BaseDAO, config: RepositoryConfig) -> BaseRepository:
        """Create a generic repository implementation."""
        
        class GenericRepository(BaseRepository):
            """Generic repository implementation."""
            
            async def _to_domain_entity(self, dao_entity):
                """Transform DAO entity to domain entity."""
                return dao_entity
            
            async def _to_dao_create(self, create_data):
                """Transform create data to DAO format."""
                return create_data
            
            async def _to_dao_update(self, update_data):
                """Transform update data to DAO format."""
                return update_data
            
            async def _criteria_to_filters(self, criteria: Dict[str, Any]) -> List[FilterCriteria]:
                """Convert business criteria to filter criteria."""
                filters = []
                for field, value in criteria.items():
                    filter_criteria = FilterCriteria(
                        field=field,
                        operator=FilterOperator.EQUALS,  # Default to equals
                        value=value
                    )
                    filters.append(filter_criteria)
                return filters
        
        return GenericRepository(dao, config)
    
    # Query Operations
    
    async def execute_query(self,
                           query: str,
                           parameters: Optional[Dict[str, Any]] = None,
                           database: str = "default") -> Any:
        """Execute raw SQL query through the abstraction layer."""
        start_time = datetime.now(timezone.utc)
        
        try:
            # Use ORM if available, otherwise fall back to database manager
            params = parameters or {}
            if self.advanced_orm:
                result = await self.advanced_orm.execute_query(query, params)
            else:
                result = await self.database_manager.execute_query(query, params, database)
            
            # Update metrics
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            self._update_query_metrics(execution_time, True)
            
            return result
            
        except Exception as e:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            self._update_query_metrics(execution_time, False)
            logger.error(f"Query execution failed: {e}")
            raise
    
    async def find_by_id(self,
                        model_class: Type[T],
                        id: Any,
                        include_relations: Optional[List[str]] = None) -> Optional[T]:
        """Find entity by ID using ORM."""
        if not self.advanced_orm:
            raise RuntimeError("Advanced ORM not initialized")
        
        return await self.advanced_orm.find_by_id(model_class, id, include_relations or [])
    
    async def find_all(self,
                      model_class: Type[T],
                      filters: Optional[Dict[str, Any]] = None,
                      order_by: Optional[List[str]] = None,
                      limit: Optional[int] = None,
                      offset: Optional[int] = None) -> List[T]:
        """Find all entities using ORM."""
        if not self.advanced_orm:
            raise RuntimeError("Advanced ORM not initialized")
        
        return await self.advanced_orm.find_all(
            model_class,
            filters or {},
            order_by or [],
            limit or 100,
            offset or 0
        )
    
    # Transaction Management
    
    async def execute_transaction(self, operations: List[Callable]) -> bool:
        """Execute multiple operations in a transaction."""
        try:
            if self.advanced_orm:
                async with await self.advanced_orm.get_async_session() as session:
                    async with session.begin():
                        for operation in operations:
                            await operation(session)
                        await session.commit()
            else:
                # Use database cluster transaction
                from ..engines import db_cluster
                async with db_cluster.get_session() as session:
                    async with session.begin():
                        for operation in operations:
                            await operation(session)
                        await session.commit()
            
            self.stats["transaction_count"] += 1
            return True
            
        except Exception as e:
            logger.error(f"Transaction failed: {e}")
            return False
    
    # Monitoring and Metrics
    
    async def _database_monitoring_loop(self):
        """Continuous database monitoring."""
        while self.enabled:
            try:
                await self._collect_database_metrics()
                await self._perform_health_checks()
                await asyncio.sleep(60)  # Monitor every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Database monitoring loop error: {e}")
                await asyncio.sleep(30)
    
    async def _collect_database_metrics(self):
        """Collect database system metrics."""
        try:
            # Collect DAO metrics
            dao_operations = 0
            for dao in self.registered_daos.values():
                if hasattr(dao, 'stats'):
                    dao_operations += dao.stats.get("operations_count", 0)
            
            # Collect repository metrics
            repo_operations = 0
            cache_hit_rate = 0.0
            for repo in self.registered_repositories.values():
                repo_stats = repo.get_statistics()
                repo_operations += repo_stats.get("operations_count", 0)
                cache_hit_rate += repo_stats.get("cache_hit_rate", 0.0)
            
            if self.registered_repositories:
                cache_hit_rate /= len(self.registered_repositories)
            
            # Collect ORM metrics
            orm_operations = 0
            if self.advanced_orm:
                orm_stats = self.advanced_orm.get_statistics()
                orm_operations = orm_stats["query_metrics"]["query_count"]
            
            # Update metrics
            self.metrics.dao_operations = dao_operations
            self.metrics.repository_operations = repo_operations
            self.metrics.orm_operations = orm_operations
            self.metrics.cache_hit_rate = cache_hit_rate
            
            # Store performance snapshot
            performance_snapshot = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metrics": {
                    "dao_operations": dao_operations,
                    "repository_operations": repo_operations,
                    "orm_operations": orm_operations,
                    "cache_hit_rate": cache_hit_rate,
                    "active_connections": self.metrics.active_connections
                }
            }
            
            self.performance_history.append(performance_snapshot)
            
            # Keep only last 100 snapshots
            if len(self.performance_history) > 100:
                self.performance_history = self.performance_history[-100:]
                
        except Exception as e:
            logger.error(f"Database metrics collection error: {e}")
    
    async def _perform_health_checks(self):
        """Perform health checks on database components."""
        try:
            # Check database manager health
            _ = self.database_manager.get_status()  # Acknowledge but don't use
            
            # Check ORM health
            orm_health = None
            if self.advanced_orm:
                orm_health = await self.advanced_orm.health_check()
            
            # Check repository health
            repo_health = {}
            for name, repo in self.registered_repositories.items():
                repo_health[name] = await repo.health_check()
            
            self.stats["last_health_check"] = datetime.now(timezone.utc)
            
            # Log any unhealthy components
            if orm_health and orm_health.get("status") != "healthy":
                logger.warning(f"⚠️ ORM health check failed: {orm_health.get('error')}")
            
            for name, health in repo_health.items():
                if health.get("status") != "healthy":
                    logger.warning(f"⚠️ Repository {name} health check failed: {health.get('error')}")
                    
        except Exception as e:
            logger.error(f"Health check error: {e}")
    
    def _update_query_metrics(self, execution_time_ms: float, success: bool):
        """Update query metrics."""
        self.metrics.total_queries += 1
        
        if success:
            self.metrics.successful_queries += 1
        else:
            self.metrics.failed_queries += 1
        
        # Update average response time
        current_avg = self.metrics.average_response_time
        total_queries = self.metrics.total_queries
        new_avg = ((current_avg * (total_queries - 1)) + execution_time_ms) / total_queries
        self.metrics.average_response_time = new_avg
    
    def get_database_status(self) -> Dict[str, Any]:
        """Get comprehensive database system status."""
        return {
            "phase4_enabled": self.enabled,
            "components": self.components,
            "statistics": self.stats,
            "metrics": {
                "total_queries": self.metrics.total_queries,
                "successful_queries": self.metrics.successful_queries,
                "failed_queries": self.metrics.failed_queries,
                "average_response_time": self.metrics.average_response_time,
                "cache_hit_rate": self.metrics.cache_hit_rate,
                "dao_operations": self.metrics.dao_operations,
                "repository_operations": self.metrics.repository_operations,
                "orm_operations": self.metrics.orm_operations
            },
            "registered_components": {
                "daos": list(self.registered_daos.keys()),
                "repositories": list(self.registered_repositories.keys())
            },
            "database_manager_status": self.database_manager.get_status(),
            "orm_statistics": self.advanced_orm.get_statistics() if self.advanced_orm else None,
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
    
    async def shutdown(self):
        """Shutdown Phase IV database components."""
        try:
            self.enabled = False
            
            # Shutdown ORM
            if self.advanced_orm:
                await self.advanced_orm.shutdown()
            
            # Clear registrations
            self.registered_daos.clear()
            self.registered_repositories.clear()
            
            logger.info("✅ Phase IV Database Abstraction System shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during Phase IV database shutdown: {e}")


# Global Phase IV database coordinator
phase4_database = Phase4DatabaseCoordinator()
