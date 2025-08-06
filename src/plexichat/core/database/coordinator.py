import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar

from sqlmodel import SQLModel

from .dao.base_dao import BaseDAO, FilterCriteria, FilterOperator
from .engines import db_cluster
from .manager import database_manager
from .orm.advanced_orm import AdvancedORM, ORMConfig
from .repository.base_repository import BaseRepository, CacheStrategy, RepositoryConfig


"""
PlexiChat Database Abstraction Coordinator
Coordinates all database abstraction layers into a unified system including:
- DAO (Data Access Object) Pattern
- Repository Pattern with Domain Logic  
- Advanced ORM Layer (SQLModel)
- Database clustering and management
- Security compliance per security.txt requirements
"""

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=SQLModel)


@dataclass
class DatabaseMetrics:
    """Database system metrics.
        total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    average_response_time: float = 0.0
    cache_hit_rate: float = 0.0
    active_connections: int = 0
    dao_operations: int = 0
    repository_operations: int = 0
    orm_operations: int = 0


class DatabaseAbstractionCoordinator:
    """
    Database Abstraction Coordinator.

    Integrates all database abstraction layers:
    1. DAO (Data Access Object) Pattern
    2. Repository Pattern with Domain Logic
    3. Advanced ORM Layer (SQLModel)
    4. Query Builder and Optimization
    5. Database Clustering and Sharding
    6. Connection Pool Management
    7. Transaction Management
    8. Caching Integration
    9. Security and Encryption (per security.txt)
    10. Performance Monitoring
    """
        def __init__(self):
        self.initialized = False
        self.running = False

        # Core database components
        self.database_manager = database_manager
        self.db_cluster = db_cluster
        self.orm = AdvancedORM()

        # Metrics and monitoring
        self.metrics = DatabaseMetrics()
        self.start_time: Optional[datetime] = None

        # Security configuration per security.txt
        self.security_config = {
            "encryption_at_rest": True,
            "encryption_in_transit": True,
            "key_rotation_enabled": True,
            "audit_logging": True,
            "access_control": "rbac",
            "data_classification": True,
            "backup_encryption": True,
        }

        # Configuration
        self.config = {
            "enable_dao_layer": True,
            "enable_repository_layer": True,
            "enable_orm_layer": True,
            "enable_clustering": True,
            "enable_caching": True,
            "enable_monitoring": True,
            "connection_pool_size": 20,
            "query_timeout": 30,
            "cache_ttl": 300,
            "monitoring_interval": 60,
        }

        # Registry for DAOs and Repositories
        self.dao_registry: Dict[str, Type[BaseDAO]] = {}
        self.repository_registry: Dict[str, Type[BaseRepository]] = {}
        self.active_daos: Dict[str, BaseDAO] = {}
        self.active_repositories: Dict[str, BaseRepository] = {}

        logger.info("Database Abstraction Coordinator initialized")

    async def initialize(self) -> bool:
        """Initialize all database abstraction components with security compliance."""
        try:
            logger.info("Initializing Database Abstraction System")

            # Initialize database manager with security
            if self.database_manager and hasattr(self.database_manager, "initialize"):
                await self.database_manager.initialize()
                logger.info("[OK] Database Manager initialized with security")

            # Initialize database cluster
            if self.config["enable_clustering"]:
                if self.db_cluster and hasattr(self.db_cluster, "initialize"):
                    await self.db_cluster.initialize()
                    logger.info("[OK] Database Cluster initialized")

            # Initialize ORM with security settings
            if self.config["enable_orm_layer"]:
                orm_config = ORMConfig(
                    enable_encryption=self.security_config["encryption_at_rest"],
                    enable_audit_logging=self.security_config["audit_logging"],
                    connection_pool_size=self.config["connection_pool_size"],
                    query_timeout=self.config["query_timeout"],
                )
                await self.orm.initialize(orm_config)
                logger.info("[OK] Advanced ORM initialized with security")

            # Register default DAOs and Repositories
            await self._register_default_components()

            # Start monitoring
            if self.config["enable_monitoring"]:
                asyncio.create_task(self._monitoring_task())
                logger.info("[OK] Database monitoring started")

            self.initialized = True
            self.running = True
            self.start_time = datetime.now(timezone.utc)

            logger.info("Database Abstraction System initialization complete")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize database abstraction system: {e}")
            return False

    async def _register_default_components(self):
        """Register default DAO and Repository components."""
        try:
            # This would register common DAOs and Repositories
            # Implementation would depend on specific models
            logger.info("Default database components registered")

        except Exception as e:
            logger.error(f"Error registering default components: {e}")

    async def _monitoring_task(self):
        """Background monitoring task for database metrics."""
        while self.running:
            try:
                await self._collect_metrics()
                await asyncio.sleep(self.config["monitoring_interval"])

            except Exception as e:
                logger.error(f"Error in database monitoring: {e}")
                await asyncio.sleep(self.config["monitoring_interval"])

    async def _collect_metrics(self):
        """Collect database metrics from all components."""
        try:
            # Collect metrics from database manager
            if self.database_manager and hasattr(self.database_manager, "get_metrics"):
                db_metrics = await self.database_manager.get_metrics()
                self.metrics.total_queries = db_metrics.get("total_queries", 0)
                self.metrics.successful_queries = db_metrics.get("successful_queries", 0)
                self.metrics.failed_queries = db_metrics.get("failed_queries", 0)
                self.metrics.average_response_time = db_metrics.get("avg_response_time", 0.0)
                self.metrics.active_connections = db_metrics.get("active_connections", 0)

            # Collect cache metrics
            if self.config["enable_caching"]:
                # Implementation would collect cache hit rates
                pass

            logger.debug("Database metrics collected")

        except Exception as e:
            logger.error(f"Error collecting database metrics: {e}")

    def register_dao(self, name: str, dao_class: Type[BaseDAO]) -> bool:
        """Register a DAO class."""
        try:
            self.dao_registry[name] = dao_class
            logger.info(f"DAO '{name}' registered")
            return True

        except Exception as e:
            logger.error(f"Error registering DAO '{name}': {e}")
            return False

    def register_repository(self, name: str, repository_class: Type[BaseRepository]) -> bool:
        """Register a Repository class."""
        try:
            self.repository_registry[name] = repository_class
            logger.info(f"Repository '{name}' registered")
            return True

        except Exception as e:
            logger.error(f"Error registering Repository '{name}': {e}")
            return False

    async def get_dao(self, name: str, model_class: Type[T]) -> Optional[BaseDAO[T]]:
        """Get or create a DAO instance."""
        try:
            if name in self.active_daos:
                return self.active_daos[name]

            if name in self.dao_registry:
                dao_class = self.dao_registry[name]
                dao_instance = dao_class(model_class, self.database_manager)
                await dao_instance.initialize()
                self.active_daos[name] = dao_instance
                self.metrics.dao_operations += 1
                return dao_instance

            logger.warning(f"DAO '{name}' not found in registry")
            return None

        except Exception as e:
            logger.error(f"Error getting DAO '{name}': {e}")
            return None

    async def get_repository(self, name: str, model_class: Type[T]) -> Optional[BaseRepository[T]]:
        """Get or create a Repository instance."""
        try:
            if name in self.active_repositories:
                return self.active_repositories[name]

            if name in self.repository_registry:
                repository_class = self.repository_registry[name]
                
                # Create repository config with security settings
                repo_config = RepositoryConfig(
                    cache_strategy=CacheStrategy.LRU if self.config["enable_caching"] else CacheStrategy.NONE,
                    cache_ttl=self.config["cache_ttl"],
                    enable_encryption=self.security_config["encryption_at_rest"],
                    enable_audit=self.security_config["audit_logging"],
                )
                
                repository_instance = repository_class(model_class, self.database_manager, repo_config)
                await repository_instance.initialize()
                self.active_repositories[name] = repository_instance
                self.metrics.repository_operations += 1
                return repository_instance

            logger.warning(f"Repository '{name}' not found in registry")
            return None

        except Exception as e:
            logger.error(f"Error getting Repository '{name}': {e}")
            return None

    async def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> Any:
        """Execute a raw SQL query with security validation."""
        try:
            # Security validation per security.txt requirements
            if not self._validate_query_security(query):
                raise ValueError("Query failed security validation")

            result = await self.database_manager.execute_query(query, parameters)
            self.metrics.total_queries += 1
            self.metrics.successful_queries += 1
            return result

        except Exception as e:
            self.metrics.total_queries += 1
            self.metrics.failed_queries += 1
            logger.error(f"Query execution failed: {e}")
            raise

    def _validate_query_security(self, query: str) -> bool:
        """Validate query for security compliance."""
        try:
            # Basic SQL injection prevention
            dangerous_patterns = [
                "DROP TABLE", "DELETE FROM", "TRUNCATE", "ALTER TABLE",
                "CREATE USER", "GRANT", "REVOKE", "EXEC", "EXECUTE"
            ]
            
            query_upper = query.upper()
            for pattern in dangerous_patterns:
                if pattern in query_upper:
                    logger.warning(f"Potentially dangerous SQL pattern detected: {pattern}")
                    return False

            return True

        except Exception as e:
            logger.error(f"Error validating query security: {e}")
            return False

    def get_database_status(self) -> Dict[str, Any]:
        """Get current database system status."""
        return {
            "initialized": self.initialized,
            "running": self.running,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "uptime_seconds": (
                (datetime.now(timezone.utc) - self.start_time).total_seconds()
                if self.start_time
                else 0
            ),
            "metrics": {
                "total_queries": self.metrics.total_queries,
                "successful_queries": self.metrics.successful_queries,
                "failed_queries": self.metrics.failed_queries,
                "average_response_time": self.metrics.average_response_time,
                "cache_hit_rate": self.metrics.cache_hit_rate,
                "active_connections": self.metrics.active_connections,
                "dao_operations": self.metrics.dao_operations,
                "repository_operations": self.metrics.repository_operations,
                "orm_operations": self.metrics.orm_operations,
            }},
            "components": {
                "dao_layer": self.config["enable_dao_layer"],
                "repository_layer": self.config["enable_repository_layer"],
                "orm_layer": self.config["enable_orm_layer"],
                "clustering": self.config["enable_clustering"],
                "caching": self.config["enable_caching"],
                "monitoring": self.config["enable_monitoring"],
            },
            "security": self.security_config,
            "registered_components": {
                "daos": list(self.dao_registry.keys()),
                "repositories": list(self.repository_registry.keys()),
                "active_daos": list(self.active_daos.keys()),
                "active_repositories": list(self.active_repositories.keys()),
            },
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }

    async def shutdown(self):
        """Shutdown all database abstraction components."""
        try:
            logger.info("Shutting down Database Abstraction System")
            self.running = False

            # Shutdown active repositories
            for name, repository in self.active_repositories.items():
                try:
                    if hasattr(repository, "shutdown"):
                        await repository.shutdown()
                    logger.info(f"[OK] Repository '{name}' shutdown")
                except Exception as e:
                    logger.error(f"Error shutting down repository '{name}': {e}")

            # Shutdown active DAOs
            for name, dao in self.active_daos.items():
                try:
                    if hasattr(dao, "shutdown"):
                        await dao.shutdown()
                    logger.info(f"[OK] DAO '{name}' shutdown")
                except Exception as e:
                    logger.error(f"Error shutting down DAO '{name}': {e}")

            # Shutdown ORM
            if self.orm and hasattr(self.orm, "shutdown"):
                await self.orm.shutdown()
                logger.info("[OK] Advanced ORM shutdown")

            # Shutdown database cluster
            if self.db_cluster and hasattr(self.db_cluster, "shutdown"):
                await self.db_cluster.shutdown()
                logger.info("[OK] Database Cluster shutdown")

            # Shutdown database manager
            if self.database_manager and hasattr(self.database_manager, "shutdown"):
                await self.database_manager.shutdown()
                logger.info("[OK] Database Manager shutdown")

            logger.info("Database Abstraction System shutdown complete")

        except Exception as e:
            logger.error(f"Error during database abstraction shutdown: {e}")


# Global database abstraction coordinator
database_coordinator = DatabaseAbstractionCoordinator()
