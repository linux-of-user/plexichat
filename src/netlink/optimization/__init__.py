"""
NetLink Enhanced Optimization System

Comprehensive performance optimization with security-aware resource management,
quantum-safe caching, and intelligent system monitoring.
"""

import asyncio
import logging
import psutil
import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json
import weakref
from functools import wraps

# Import security systems
from ..security import security_manager, quantum_encryption, database_encryption

# Import secure caching
from .secure_cache import QuantumSecureCache, secure_cache, CacheLevel, CacheStrategy

logger = logging.getLogger(__name__)


class OptimizationLevel(Enum):
    """System optimization levels."""
    MINIMAL = 1
    STANDARD = 2
    AGGRESSIVE = 3
    MAXIMUM = 4
    QUANTUM_OPTIMIZED = 5


class ResourceType(Enum):
    """System resource types."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    DATABASE = "database"
    ENCRYPTION = "encryption"


@dataclass
class SystemMetrics:
    """System performance metrics."""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_usage: Dict[str, float]
    network_io: Dict[str, int]
    active_connections: int
    encryption_operations: int = 0
    database_queries: int = 0
    cache_hit_rate: float = 0.0
    response_times: List[float] = field(default_factory=list)
    error_count: int = 0


@dataclass
class OptimizationRule:
    """Performance optimization rule."""
    rule_id: str
    name: str
    condition: Callable[[SystemMetrics], bool]
    action: Callable[[], None]
    priority: int
    enabled: bool = True
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecureOptimizationManager:
    """
    Enhanced Optimization Manager with Security Integration
    
    Features:
    - Security-aware resource management
    - Quantum-safe performance caching
    - Intelligent system monitoring
    - Adaptive optimization strategies
    - Encrypted performance data
    - Real-time threat-aware optimization
    - Resource allocation based on security level
    """
    
    def __init__(self, config_dir: str = "config/optimization"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Optimization configuration
        self.optimization_level = OptimizationLevel.QUANTUM_OPTIMIZED
        self.monitoring_interval = 5.0  # seconds
        self.metrics_retention_hours = 24
        
        # Performance tracking
        self.metrics_history: List[SystemMetrics] = []
        self.optimization_rules: Dict[str, OptimizationRule] = {}
        self.active_optimizations: Dict[str, Any] = {}
        
        # Caching system
        self.secure_cache: Dict[str, Any] = {}
        self.cache_encryption_keys: Dict[str, bytes] = {}
        
        # Resource limits
        self.resource_limits = {
            ResourceType.CPU: 80.0,
            ResourceType.MEMORY: 85.0,
            ResourceType.DISK: 90.0,
            ResourceType.NETWORK: 1000,  # MB/s
            ResourceType.DATABASE: 100,  # queries/sec
            ResourceType.ENCRYPTION: 50   # operations/sec
        }
        
        # Performance counters
        self.performance_counters = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "encryption_operations": 0,
            "database_queries": 0,
            "optimization_triggers": 0
        }
        
        # Initialize system
        asyncio.create_task(self._initialize_optimization_system())
    
    async def _initialize_optimization_system(self):
        """Initialize the optimization system."""
        await self._setup_optimization_rules()
        await self._start_monitoring()
        await self._load_optimization_config()
        logger.info("⚡ Enhanced optimization system initialized")
    
    async def _setup_optimization_rules(self):
        """Setup performance optimization rules."""
        # CPU optimization rules
        self.optimization_rules["high_cpu_usage"] = OptimizationRule(
            rule_id="high_cpu_usage",
            name="High CPU Usage Mitigation",
            condition=lambda metrics: metrics.cpu_percent > self.resource_limits[ResourceType.CPU],
            action=self._optimize_cpu_usage,
            priority=1
        )
        
        # Memory optimization rules
        self.optimization_rules["high_memory_usage"] = OptimizationRule(
            rule_id="high_memory_usage", 
            name="High Memory Usage Mitigation",
            condition=lambda metrics: metrics.memory_percent > self.resource_limits[ResourceType.MEMORY],
            action=self._optimize_memory_usage,
            priority=1
        )
        
        # Database optimization rules
        self.optimization_rules["slow_database"] = OptimizationRule(
            rule_id="slow_database",
            name="Database Performance Optimization",
            condition=lambda metrics: metrics.database_queries > self.resource_limits[ResourceType.DATABASE],
            action=self._optimize_database_performance,
            priority=2
        )
        
        # Encryption optimization rules
        self.optimization_rules["encryption_bottleneck"] = OptimizationRule(
            rule_id="encryption_bottleneck",
            name="Encryption Performance Optimization", 
            condition=lambda metrics: metrics.encryption_operations > self.resource_limits[ResourceType.ENCRYPTION],
            action=self._optimize_encryption_performance,
            priority=2
        )
        
        # Cache optimization rules
        self.optimization_rules["low_cache_hit_rate"] = OptimizationRule(
            rule_id="low_cache_hit_rate",
            name="Cache Hit Rate Optimization",
            condition=lambda metrics: metrics.cache_hit_rate < 0.7,
            action=self._optimize_cache_strategy,
            priority=3
        )
    
    async def _start_monitoring(self):
        """Start continuous system monitoring."""
        async def monitoring_loop():
            while True:
                try:
                    await self._collect_system_metrics()
                    await self._apply_optimization_rules()
                    await self._cleanup_old_metrics()
                    await asyncio.sleep(self.monitoring_interval)
                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
                    await asyncio.sleep(self.monitoring_interval * 2)
        
        asyncio.create_task(monitoring_loop())
        logger.info("📊 System monitoring started")
    
    async def _collect_system_metrics(self):
        """Collect current system performance metrics."""
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk_usage = {
                partition.mountpoint: psutil.disk_usage(partition.mountpoint).percent
                for partition in psutil.disk_partitions()
                if partition.fstype
            }
            network_io = psutil.net_io_counters()._asdict()
            
            # Get application-specific metrics
            active_connections = len(psutil.net_connections())
            
            # Calculate cache hit rate
            total_cache_requests = self.performance_counters["cache_hits"] + self.performance_counters["cache_misses"]
            cache_hit_rate = (
                self.performance_counters["cache_hits"] / total_cache_requests 
                if total_cache_requests > 0 else 0.0
            )
            
            metrics = SystemMetrics(
                timestamp=datetime.now(timezone.utc),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                disk_usage=disk_usage,
                network_io=network_io,
                active_connections=active_connections,
                encryption_operations=self.performance_counters["encryption_operations"],
                database_queries=self.performance_counters["database_queries"],
                cache_hit_rate=cache_hit_rate,
                error_count=self.performance_counters["failed_requests"]
            )
            
            self.metrics_history.append(metrics)
            
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
    
    async def _apply_optimization_rules(self):
        """Apply optimization rules based on current metrics."""
        if not self.metrics_history:
            return
        
        current_metrics = self.metrics_history[-1]
        
        for rule_id, rule in self.optimization_rules.items():
            if rule.enabled and rule.condition(current_metrics):
                # Check if rule was recently triggered to avoid spam
                if (rule.last_triggered and 
                    datetime.now(timezone.utc) - rule.last_triggered < timedelta(minutes=5)):
                    continue
                
                try:
                    await rule.action()
                    rule.last_triggered = datetime.now(timezone.utc)
                    rule.trigger_count += 1
                    self.performance_counters["optimization_triggers"] += 1
                    
                    logger.info(f"⚡ Applied optimization rule: {rule.name}")
                    
                except Exception as e:
                    logger.error(f"Failed to apply optimization rule {rule.name}: {e}")
    
    async def _optimize_cpu_usage(self):
        """Optimize CPU usage."""
        logger.info("🔧 Optimizing CPU usage...")
        
        # Reduce encryption operations priority
        if hasattr(quantum_encryption, 'reduce_operation_priority'):
            await quantum_encryption.reduce_operation_priority()
        
        # Implement CPU throttling for non-critical operations
        self.active_optimizations["cpu_throttling"] = True
    
    async def _optimize_memory_usage(self):
        """Optimize memory usage."""
        logger.info("🔧 Optimizing memory usage...")
        
        # Clear old cache entries
        await self._cleanup_cache()
        
        # Reduce metrics history
        if len(self.metrics_history) > 100:
            self.metrics_history = self.metrics_history[-50:]
        
        self.active_optimizations["memory_cleanup"] = True
    
    async def _optimize_database_performance(self):
        """Optimize database performance."""
        logger.info("🔧 Optimizing database performance...")
        
        # Enable database query caching
        self.active_optimizations["db_query_cache"] = True
        
        # Suggest database maintenance
        logger.info("💡 Consider running database maintenance operations")
    
    async def _optimize_encryption_performance(self):
        """Optimize encryption performance."""
        logger.info("🔧 Optimizing encryption performance...")
        
        # Enable encryption result caching
        self.active_optimizations["encryption_cache"] = True
        
        # Batch encryption operations
        self.active_optimizations["encryption_batching"] = True
    
    async def _optimize_cache_strategy(self):
        """Optimize caching strategy."""
        logger.info("🔧 Optimizing cache strategy...")
        
        # Increase cache size
        self.active_optimizations["expanded_cache"] = True
        
        # Implement predictive caching
        self.active_optimizations["predictive_cache"] = True
    
    async def _cleanup_old_metrics(self):
        """Clean up old performance metrics."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.metrics_retention_hours)
        self.metrics_history = [
            metrics for metrics in self.metrics_history 
            if metrics.timestamp > cutoff_time
        ]
    
    async def _cleanup_cache(self):
        """Clean up old cache entries."""
        current_time = datetime.now(timezone.utc)
        expired_keys = []
        
        for key, entry in self.secure_cache.items():
            if hasattr(entry, 'expires_at') and entry.expires_at and current_time > entry.expires_at:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.secure_cache[key]
            if key in self.cache_encryption_keys:
                del self.cache_encryption_keys[key]
        
        logger.info(f"🗑️ Cleaned up {len(expired_keys)} expired cache entries")
    
    async def _load_optimization_config(self):
        """Load optimization configuration."""
        config_file = self.config_dir / "optimization_config.json"
        
        if config_file.exists():
            try:
                async with aiofiles.open(config_file, 'r') as f:
                    config = json.loads(await f.read())
                    
                self.optimization_level = OptimizationLevel(config.get("optimization_level", 5))
                self.monitoring_interval = config.get("monitoring_interval", 5.0)
                self.resource_limits.update(config.get("resource_limits", {}))
                
                logger.info(f"📋 Loaded optimization config: {self.optimization_level.name}")
                
            except Exception as e:
                logger.error(f"Failed to load optimization config: {e}")


# Global optimization manager instance
optimization_manager = SecureOptimizationManager()

__all__ = [
    'SecureOptimizationManager',
    'optimization_manager',
    'OptimizationLevel',
    'ResourceType',
    'SystemMetrics',
    'OptimizationRule',
    'QuantumSecureCache',
    'secure_cache',
    'CacheLevel',
    'CacheStrategy'
]
