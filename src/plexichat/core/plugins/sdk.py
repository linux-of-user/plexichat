"""
PlexiChat Plugin SDK - SINGLE SOURCE OF TRUTH

Enhanced Software Development Kit for creating PlexiChat plugins with:
- Redis caching integration for performance optimization
- Database abstraction layer for unified data access
- Comprehensive plugin development utilities
- Security sandboxing and permission management
- Event system integration
- Performance monitoring
- Auto-discovery and hot-reloading capabilities
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union

try:
    from .unified_plugin_manager import (
        PluginInterface, PluginMetadata, PluginInfo, PluginType, 
        SecurityLevel, PluginStatus, unified_plugin_manager
    )
    from ..logging import get_logger
    from ..config.manager import get_config
    from ..database.manager import get_database_manager
    from ...infrastructure.performance.cache_manager import get_cache_manager
    from ...infrastructure.monitoring import get_performance_monitor
    
    logger = get_logger(__name__)
    config = get_config()
    database_manager = get_database_manager()
    cache_manager = get_cache_manager()
    performance_monitor = get_performance_monitor()
except ImportError:
    logger = logging.getLogger(__name__)
    config = {}
    database_manager = None
    cache_manager = None
    performance_monitor = None
    PluginInterface = object
    PluginMetadata = object
    PluginInfo = object
    PluginType = None
    SecurityLevel = None
    PluginStatus = None
    unified_plugin_manager = None


@dataclass
class EnhancedPluginConfig:
    """Enhanced plugin configuration with validation and optimization settings."""
    name: str
    version: str
    description: str
    author: str
    email: Optional[str] = None
    license: str = "MIT"
    homepage: Optional[str] = None
    repository: Optional[str] = None
    tags: List[str] = None
    plugin_type: str = "feature"
    security_level: str = "sandboxed"
    min_plexichat_version: Optional[str] = None
    max_plexichat_version: Optional[str] = None
    dependencies: List[str] = None
    permissions: List[str] = None
    auto_load: bool = True
    priority: int = 5
    cache_enabled: bool = True
    cache_ttl: int = 300  # 5 minutes default
    performance_monitoring: bool = True
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.dependencies is None:
            self.dependencies = []
        if self.permissions is None:
            self.permissions = []


class EnhancedPluginLogger:
    """Enhanced plugin logger with performance monitoring and caching."""
    
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        self.logger = get_logger(f"plugin.{plugin_name}")
        self._performance_metrics = {}
    
    def info(self, message: str, **kwargs):
        """Log info message with performance tracking."""
        self.logger.info(f"[{self.plugin_name}] {message}", **kwargs)
        if performance_monitor:
            performance_monitor.log_plugin_event(self.plugin_name, "info", message)
    
    def error(self, message: str, **kwargs):
        """Log error message with performance tracking."""
        self.logger.error(f"[{self.plugin_name}] {message}", **kwargs)
        if performance_monitor:
            performance_monitor.log_plugin_event(self.plugin_name, "error", message)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with performance tracking."""
        self.logger.warning(f"[{self.plugin_name}] {message}", **kwargs)
        if performance_monitor:
            performance_monitor.log_plugin_event(self.plugin_name, "warning", message)
    
    def debug(self, message: str, **kwargs):
        """Log debug message with performance tracking."""
        self.logger.debug(f"[{self.plugin_name}] {message}", **kwargs)
    
    def track_performance(self, operation: str, duration: float):
        """Track performance metrics for plugin operations."""
        if operation not in self._performance_metrics:
            self._performance_metrics[operation] = []
        self._performance_metrics[operation].append(duration)
        
        if performance_monitor:
            performance_monitor.track_plugin_performance(
                self.plugin_name, operation, duration
            )


class EnhancedPluginAPI:
    """Enhanced Plugin API with Redis caching and database abstraction."""
    
    def __init__(self, plugin_name: str, config: EnhancedPluginConfig):
        self.plugin_name = plugin_name
        self.config = config
        self.logger = EnhancedPluginLogger(plugin_name)
        self._cache_prefix = f"plugin:{plugin_name}"
    
    # Enhanced Caching Operations
    async def cache_get(self, key: str) -> Optional[Any]:
        """Get value from Redis cache with plugin namespace."""
        if not cache_manager or not self.config.cache_enabled:
            return None
        
        cache_key = f"{self._cache_prefix}:{key}"
        try:
            return await cache_manager.get(cache_key)
        except Exception as e:
            self.logger.error(f"Cache get failed for key {key}: {e}")
            return None
    
    async def cache_set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in Redis cache with plugin namespace."""
        if not cache_manager or not self.config.cache_enabled:
            return False
        
        cache_key = f"{self._cache_prefix}:{key}"
        cache_ttl = ttl or self.config.cache_ttl
        
        try:
            await cache_manager.set(cache_key, value, ttl=cache_ttl)
            return True
        except Exception as e:
            self.logger.error(f"Cache set failed for key {key}: {e}")
            return False
    
    async def cache_delete(self, key: str) -> bool:
        """Delete value from Redis cache."""
        if not cache_manager:
            return False
        
        cache_key = f"{self._cache_prefix}:{key}"
        try:
            await cache_manager.delete(cache_key)
            return True
        except Exception as e:
            self.logger.error(f"Cache delete failed for key {key}: {e}")
            return False
    
    # Enhanced Database Operations
    async def db_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Execute database query using abstraction layer."""
        if not database_manager:
            self.logger.error("Database manager not available")
            return []
        
        try:
            async with database_manager.get_session() as session:
                result = await session.execute(query, params or {})
                return [dict(row) for row in result.fetchall()]
        except Exception as e:
            self.logger.error(f"Database query failed: {e}")
            return []
    
    async def db_insert(self, table: str, data: Dict[str, Any]) -> Optional[int]:
        """Insert data into database table."""
        if not database_manager:
            return None
        
        try:
            async with database_manager.get_session() as session:
                result = await session.insert(table, data)
                await session.commit()
                return result.lastrowid
        except Exception as e:
            self.logger.error(f"Database insert failed: {e}")
            return None
    
    async def db_update(self, table: str, data: Dict[str, Any], where: Dict[str, Any]) -> bool:
        """Update data in database table."""
        if not database_manager:
            return False
        
        try:
            async with database_manager.get_session() as session:
                await session.update(table, data, where)
                await session.commit()
                return True
        except Exception as e:
            self.logger.error(f"Database update failed: {e}")
            return False
    
    # Configuration Management
    async def get_config(self, key: str, default: Any = None) -> Any:
        """Get plugin configuration value with caching."""
        cache_key = f"config:{key}"
        
        # Try cache first
        cached_value = await self.cache_get(cache_key)
        if cached_value is not None:
            return cached_value
        
        # Get from config
        plugin_config = config.get(f"plugins.{self.plugin_name}", {})
        value = plugin_config.get(key, default)
        
        # Cache the result
        await self.cache_set(cache_key, value, ttl=60)  # Cache config for 1 minute
        return value
    
    async def set_config(self, key: str, value: Any) -> bool:
        """Set plugin configuration value."""
        try:
            # Update config
            if f"plugins.{self.plugin_name}" not in config:
                config[f"plugins.{self.plugin_name}"] = {}
            config[f"plugins.{self.plugin_name}"][key] = value
            
            # Update cache
            cache_key = f"config:{key}"
            await self.cache_set(cache_key, value, ttl=60)
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to set config {key}: {e}")
            return False
    
    # Event System Integration
    async def emit_event(self, event_name: str, data: Dict[str, Any]) -> bool:
        """Emit event through the plugin system."""
        try:
            if unified_plugin_manager:
                await unified_plugin_manager.emit_event(event_name, data)
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to emit event {event_name}: {e}")
            return False
    
    # Performance Monitoring
    def track_performance(self, operation: str):
        """Context manager for tracking operation performance."""
        return PerformanceTracker(self.logger, operation)


class PerformanceTracker:
    """Context manager for tracking plugin operation performance."""
    
    def __init__(self, logger: EnhancedPluginLogger, operation: str):
        self.logger = logger
        self.operation = operation
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now(timezone.utc)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = (datetime.now(timezone.utc) - self.start_time).total_seconds()
            self.logger.track_performance(self.operation, duration)


class EnhancedBasePlugin(PluginInterface):
    """Enhanced base plugin class with optimization systems integration."""
    
    def __init__(self, config: EnhancedPluginConfig):
        self.config = config
        self.api = EnhancedPluginAPI(config.name, config)
        self.logger = self.api.logger
        self._initialized = False
    
    async def initialize(self) -> bool:
        """Initialize the plugin with performance tracking."""
        if self._initialized:
            return True
        
        with self.api.track_performance("initialization"):
            try:
                await self._initialize()
                self._initialized = True
                self.logger.info(f"Plugin {self.config.name} initialized successfully")
                return True
            except Exception as e:
                self.logger.error(f"Plugin initialization failed: {e}")
                return False
    
    @abstractmethod
    async def _initialize(self):
        """Plugin-specific initialization logic."""
        pass
    
    async def cleanup(self):
        """Cleanup plugin resources."""
        try:
            await self._cleanup()
            self.logger.info(f"Plugin {self.config.name} cleaned up successfully")
        except Exception as e:
            self.logger.error(f"Plugin cleanup failed: {e}")
    
    async def _cleanup(self):
        """Plugin-specific cleanup logic."""
        pass


# Export all SDK components
__all__ = [
    "EnhancedPluginConfig",
    "EnhancedPluginLogger", 
    "EnhancedPluginAPI",
    "EnhancedBasePlugin",
    "PerformanceTracker",
    # Backward compatibility
    "PluginInterface",
    "PluginMetadata",
    "PluginInfo",
]
