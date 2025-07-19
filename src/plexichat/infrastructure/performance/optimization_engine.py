# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import gc
import logging
import sys
import tracemalloc
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


import psutil
import psutil
import psutil
import psutil
import psutil
import psutil
import psutil
import psutil
import psutil
import psutil
import psutil
import psutil

"""
import time
PlexiChat Performance Optimization Engine

Advanced performance optimization with specific success metrics:
- Real-time performance monitoring
- Intelligent caching strategies
- Database query optimization
- Memory management and garbage collection
- Network optimization and compression
- CPU usage optimization
- Predictive performance scaling
"""

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """Performance metric data point."""
    metric_name: str
    value: float
    unit: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    category: str = "general"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "metric_name": self.metric_name,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat(),
            "category": self.category
        }


@dataclass
class PerformanceTarget:
    """Performance optimization target."""
    metric_name: str
    target_value: float
    current_value: float
    improvement_percentage: float
    priority: int = 1  # 1=high, 2=medium, 3=low
    optimization_strategy: str = ""

    @property
    def is_achieved(self) -> bool:
        """Check if target is achieved."""
        return self.current_value >= self.target_value

    @property
    def progress_percentage(self) -> float:
        """Calculate progress towards target."""
        if self.target_value == 0:
            return 100.0
        return min((self.current_value / self.target_value) * 100, 100.0)


class PerformanceMonitor:
    """Real-time performance monitoring system."""

    def __init__(self, max_history: int = 1000):
        self.metrics_history: Dict[str, deque] = {}
        self.max_history = max_history
        self.monitoring_active = False
        self.alert_thresholds: Dict[str, float] = {}

        # Performance targets
        self.targets = {
            "response_time_ms": PerformanceTarget(
                metric_name="response_time_ms",
                target_value=100.0,  # Target: <100ms response time
                current_value=0.0,
                improvement_percentage=50.0,
                priority=1,
                optimization_strategy="caching_and_database_optimization"
            ),
            "throughput_rps": PerformanceTarget(
                metric_name="throughput_rps",
                target_value=1000.0,  # Target: 1000 requests/second
                current_value=0.0,
                improvement_percentage=200.0,
                priority=1,
                optimization_strategy="async_processing_and_load_balancing"
            ),
            "memory_usage_mb": PerformanceTarget(
                metric_name="memory_usage_mb",
                target_value=512.0,  # Target: <512MB memory usage
                current_value=0.0,
                improvement_percentage=-30.0,  # Reduce by 30%
                priority=2,
                optimization_strategy="memory_optimization_and_gc_tuning"
            ),
            "cpu_usage_percent": PerformanceTarget(
                metric_name="cpu_usage_percent",
                target_value=70.0,  # Target: <70% CPU usage
                current_value=0.0,
                improvement_percentage=-25.0,  # Reduce by 25%
                priority=2,
                optimization_strategy="cpu_optimization_and_async_processing"
            ),
            "database_query_time_ms": PerformanceTarget(
                metric_name="database_query_time_ms",
                target_value=50.0,  # Target: <50ms query time
                current_value=0.0,
                improvement_percentage=60.0,
                priority=1,
                optimization_strategy="query_optimization_and_indexing"
            )
        }

        # Set default alert thresholds
        self.alert_thresholds = {
            "response_time_ms": 500.0,
            "memory_usage_mb": 1024.0,
            "cpu_usage_percent": 90.0,
            "database_query_time_ms": 200.0,
            "error_rate_percent": 5.0
        }

    def start_monitoring(self):
        """Start performance monitoring."""
        if not self.monitoring_active:
            self.monitoring_active = True
            asyncio.create_task(self._monitoring_loop())
            logger.info("Performance monitoring started")

    def stop_monitoring(self):
        """Stop performance monitoring."""
        self.monitoring_active = False
        logger.info("Performance monitoring stopped")

    def record_metric(self, metric: PerformanceMetric):
        """Record performance metric."""
        if metric.metric_name not in self.metrics_history:
            self.metrics_history[metric.metric_name] = deque(maxlen=self.max_history)

        self.metrics_history[metric.metric_name].append(metric)

        # Update current value in targets
        if metric.metric_name in self.targets:
            self.targets[metric.metric_name].current_value = metric.value

        # Check alert thresholds
        self._check_alert_threshold(metric)

    def _check_alert_threshold(self, metric: PerformanceMetric):
        """Check if metric exceeds alert threshold."""
        threshold = self.alert_thresholds.get(metric.metric_name)
        if threshold and metric.value > threshold:
            logger.warning(f"Performance alert: {metric.metric_name} = {metric.value} {metric.unit} (threshold: {threshold})")

    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(5)  # Collect every 5 seconds
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")

    async def _collect_system_metrics(self):
        """Collect system performance metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.record_metric(PerformanceMetric(
                metric_name="cpu_usage_percent",
                value=cpu_percent,
                unit="percent",
                category="system"
            ))

            # Memory usage
            memory = psutil.virtual_memory()
            memory_mb = memory.used / 1024 / 1024
            self.record_metric(PerformanceMetric(
                metric_name="memory_usage_mb",
                value=memory_mb,
                unit="MB",
                category="system"
            ))

            # Memory usage percentage
            self.record_metric(PerformanceMetric(
                metric_name="memory_usage_percent",
                value=memory.percent,
                unit="percent",
                category="system"
            ))

            # Disk I/O
            disk_io = psutil.disk_io_counters()
            if disk_io:
                self.record_metric(PerformanceMetric(
                    metric_name="disk_read_mb_per_sec",
                    value=disk_io.read_bytes / 1024 / 1024,
                    unit="MB/s",
                    category="system"
                ))

                self.record_metric(PerformanceMetric(
                    metric_name="disk_write_mb_per_sec",
                    value=disk_io.write_bytes / 1024 / 1024,
                    unit="MB/s",
                    category="system"
                ))

            # Network I/O
            network_io = psutil.net_io_counters()
            if network_io:
                self.record_metric(PerformanceMetric(
                    metric_name="network_sent_mb_per_sec",
                    value=network_io.bytes_sent / 1024 / 1024,
                    unit="MB/s",
                    category="system"
                ))

                self.record_metric(PerformanceMetric(
                    metric_name="network_recv_mb_per_sec",
                    value=network_io.bytes_recv / 1024 / 1024,
                    unit="MB/s",
                    category="system"
                ))

        except Exception as e:
            logger.error(f"System metrics collection failed: {e}")

    def get_metric_history(self, metric_name: str, limit: int = 100) -> List[PerformanceMetric]:
        """Get metric history."""
        if metric_name in self.metrics_history:
            history = list(self.metrics_history[metric_name])
            return history[-limit:] if limit else history
        return []

    def get_average_metric(self, metric_name: str, minutes: int = 5) -> Optional[float]:
        """Get average metric value over time period."""
        if metric_name not in self.metrics_history:
            return None

        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        recent_metrics = [
            m for m in self.metrics_history[metric_name]
            if m.timestamp > cutoff_time
        ]

        if recent_metrics:
            return sum(m.value for m in recent_metrics) / len(recent_metrics)
        return None

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        summary = {
            "targets": {},
            "current_metrics": {},
            "alerts": [],
            "overall_score": 0.0
        }

        # Calculate target progress
        total_progress = 0.0
        achieved_targets = 0

        for target_name, target in self.targets.items():
            target_info = {
                "target_value": target.target_value,
                "current_value": target.current_value,
                "progress_percentage": target.progress_percentage,
                "is_achieved": target.is_achieved,
                "priority": target.priority,
                "optimization_strategy": target.optimization_strategy
            }
            summary["targets"][target_name] = target_info

            total_progress += target.progress_percentage
            if target.is_achieved:
                achieved_targets += 1

        # Calculate overall performance score
        if self.targets:
            summary["overall_score"] = total_progress / len(self.targets)
            summary["achieved_targets"] = achieved_targets
            summary["total_targets"] = len(self.targets)

        # Get current metrics
        for metric_name in self.metrics_history:
            if self.metrics_history[metric_name]:
                latest_metric = self.metrics_history[metric_name][-1]
                summary["current_metrics"][metric_name] = {
                    "value": latest_metric.value,
                    "unit": latest_metric.unit,
                    "timestamp": latest_metric.timestamp.isoformat()
                }

        return summary


class IntelligentCache:
    """Intelligent caching system with adaptive strategies."""

    def __init__(self, max_size: int = 10000):
        self.cache: Dict[str, Any] = {}
        self.access_times: Dict[str, datetime] = {}
        self.access_counts: Dict[str, int] = {}
        self.max_size = max_size

        # Cache statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0

        # Adaptive parameters
        self.ttl_seconds = 300  # 5 minutes default TTL
        self.adaptive_ttl = True

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if key in self.cache:
            # Check TTL
            if self._is_expired(key):
                self._remove(key)
                self.misses += 1
                return None

            # Update access statistics
            self.access_times[key] = datetime.now(timezone.utc)
            self.access_counts[key] = self.access_counts.get(key, 0) + 1
            self.hits += 1

            return self.cache[key]

        self.misses += 1
        return None

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None):
        """Set value in cache."""
        # Evict if cache is full
        if len(self.cache) >= self.max_size:
            self._evict_lru()

        self.cache[key] = value
        self.access_times[key] = datetime.now(timezone.utc)
        self.access_counts[key] = 1

        # Set custom TTL if provided
        if ttl_seconds:
            self.cache[f"{key}_ttl"] = ttl_seconds

    def _is_expired(self, key: str) -> bool:
        """Check if cache entry is expired."""
        if key not in self.access_times:
            return True

        # Get TTL for this key
        ttl = self.cache.get(f"{key}_ttl", self.ttl_seconds)

        age = (datetime.now(timezone.utc) - self.access_times[key]).total_seconds()
        return age > ttl

    def _remove(self, key: str):
        """Remove key from cache."""
        self.cache.pop(key, None)
        self.access_times.pop(key, None)
        self.access_counts.pop(key, None)
        self.cache.pop(f"{key}_ttl", None)

    def _evict_lru(self):
        """Evict least recently used item."""
        if not self.access_times:
            return

        # Find LRU key
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        self._remove(lru_key)
        self.evictions += 1

    def clear(self):
        """Clear all cache entries."""
        self.cache.clear()
        self.access_times.clear()
        self.access_counts.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate_percent": hit_rate,
            "evictions": self.evictions,
            "memory_usage_estimate_mb": self._estimate_memory_usage()
        }

    def _estimate_memory_usage(self) -> float:
        """Estimate cache memory usage."""
        # Rough estimation
        total_size = 0

        for key, value in self.cache.items():
            total_size += sys.getsizeof(key) + sys.getsizeof(value)

        return total_size / 1024 / 1024  # Convert to MB


class DatabaseOptimizer:
    """Database query optimization and performance tuning."""

    def __init__(self):
        self.query_cache = IntelligentCache(max_size=5000)
        self.slow_queries: List[Dict[str, Any]] = []
        self.query_stats: Dict[str, Dict[str, Any]] = {}
        self.optimization_suggestions: List[Dict[str, Any]] = []

        # Performance thresholds
        self.slow_query_threshold_ms = 100
        self.cache_hit_target = 80.0  # 80% cache hit rate target

    def record_query(self, query: str, execution_time_ms: float, result_size: int = 0):
        """Record database query performance."""
        query_hash = hash(query)

        # Update query statistics
        if query_hash not in self.query_stats:
            self.query_stats[query_hash] = {
                "query": query[:200] + "..." if len(query) > 200 else query,
                "total_executions": 0,
                "total_time_ms": 0.0,
                "average_time_ms": 0.0,
                "min_time_ms": float('inf'),
                "max_time_ms": 0.0,
                "last_executed": None
            }

        stats = self.query_stats[query_hash]
        stats["total_executions"] += 1
        stats["total_time_ms"] += execution_time_ms
        stats["average_time_ms"] = stats["total_time_ms"] / stats["total_executions"]
        stats["min_time_ms"] = min(stats["min_time_ms"], execution_time_ms)
        stats["max_time_ms"] = max(stats["max_time_ms"], execution_time_ms)
        stats["last_executed"] = datetime.now(timezone.utc)

        # Record slow queries
        if execution_time_ms > self.slow_query_threshold_ms:
            self.slow_queries.append({
                "query": query,
                "execution_time_ms": execution_time_ms,
                "result_size": result_size,
                "timestamp": datetime.now(timezone.utc)
            })

            # Keep only recent slow queries
            if len(self.slow_queries) > 1000:
                self.slow_queries = self.slow_queries[-500:]

        # Record performance metric
        performance_monitor.record_metric(PerformanceMetric(
            metric_name="database_query_time_ms",
            value=execution_time_ms,
            unit="ms",
            category="database"
        ))

    def get_optimization_suggestions(self) -> List[Dict[str, Any]]:
        """Get database optimization suggestions."""
        suggestions = []

        # Analyze slow queries
        if self.slow_queries:
            recent_slow = [q for q in self.slow_queries
                          if (datetime.now(timezone.utc) - q["timestamp"]).total_seconds() < 3600]

            if len(recent_slow) > 10:
                suggestions.append({
                    "type": "slow_queries",
                    "priority": "high",
                    "description": f"Found {len(recent_slow)} slow queries in the last hour",
                    "recommendation": "Consider adding database indexes or optimizing query structure",
                    "impact": "High - directly affects response time"
                })

        # Analyze cache hit rate
        cache_stats = self.query_cache.get_stats()
        if cache_stats["hit_rate_percent"] < self.cache_hit_target:
            suggestions.append({
                "type": "cache_optimization",
                "priority": "medium",
                "description": f"Query cache hit rate is {cache_stats['hit_rate_percent']:.1f}% (target: {self.cache_hit_target}%)",
                "recommendation": "Increase cache size or adjust TTL settings",
                "impact": "Medium - improves query response time"
            })

        # Analyze query patterns
        frequent_queries = sorted(
            self.query_stats.values(),
            key=lambda x: x["total_executions"],
            reverse=True
        )[:10]

        for query_stat in frequent_queries:
            if query_stat["average_time_ms"] > self.slow_query_threshold_ms:
                suggestions.append({
                    "type": "frequent_slow_query",
                    "priority": "high",
                    "description": f"Frequently executed query is slow (avg: {query_stat['average_time_ms']:.1f}ms)",
                    "recommendation": "Optimize this query as it has high impact on overall performance",
                    "query": query_stat["query"],
                    "impact": "High - affects many requests"
                })

        return suggestions

    def get_database_performance_summary(self) -> Dict[str, Any]:
        """Get database performance summary."""
        cache_stats = self.query_cache.get_stats()

        # Calculate average query time
        if self.query_stats:
            total_time = sum(stat["total_time_ms"] for stat in self.query_stats.values())
            total_queries = sum(stat["total_executions"] for stat in self.query_stats.values())
            avg_query_time = total_time / total_queries if total_queries > 0 else 0
        else:
            avg_query_time = 0

        return {
            "average_query_time_ms": avg_query_time,
            "total_queries_executed": sum(stat["total_executions"] for stat in self.query_stats.values()),
            "unique_queries": len(self.query_stats),
            "slow_queries_count": len(self.slow_queries),
            "cache_hit_rate_percent": cache_stats["hit_rate_percent"],
            "optimization_suggestions": len(self.get_optimization_suggestions())
        }


class MemoryOptimizer:
    """Memory usage optimization and garbage collection tuning."""

    def __init__(self):
        self.memory_snapshots: List[Dict[str, Any]] = []
        self.gc_stats: List[Dict[str, Any]] = []
        self.object_pools: Dict[str, List[Any]] = {}

        # Memory optimization settings
        self.gc_threshold_mb = 100  # Trigger GC when memory increases by 100MB
        self.last_memory_usage = 0

    def take_memory_snapshot(self) -> Dict[str, Any]:
        """Take memory usage snapshot."""
        try:
            # Get current memory usage
            memory = psutil.virtual_memory()
            process = psutil.Process()
            process_memory = process.memory_info()

            snapshot = {
                "timestamp": datetime.now(timezone.utc),
                "system_memory_mb": memory.used / 1024 / 1024,
                "system_memory_percent": memory.percent,
                "process_memory_mb": process_memory.rss / 1024 / 1024,
                "gc_counts": gc.get_count(),
                "gc_stats": gc.get_stats() if hasattr(gc, 'get_stats') else []
            }

            # Add tracemalloc info if available
            if tracemalloc.is_tracing():
                current, peak = tracemalloc.get_traced_memory()
                snapshot["traced_memory_mb"] = current / 1024 / 1024
                snapshot["peak_memory_mb"] = peak / 1024 / 1024

            self.memory_snapshots.append(snapshot)

            # Keep only recent snapshots
            if len(self.memory_snapshots) > 1000:
                self.memory_snapshots = self.memory_snapshots[-500:]

            return snapshot

        except Exception as e:
            logger.error(f"Memory snapshot failed: {e}")
            return {}

    def optimize_memory(self):
        """Perform memory optimization."""
        try:
            # Force garbage collection
            collected = gc.collect()

            # Record GC stats
            gc_stat = {
                "timestamp": datetime.now(timezone.utc),
                "objects_collected": collected,
                "gc_counts": gc.get_count()
            }
            self.gc_stats.append(gc_stat)

            # Take memory snapshot after GC
            snapshot = self.take_memory_snapshot()

            logger.info(f"Memory optimization: collected {collected} objects, memory usage: {snapshot.get('process_memory_mb', 0):.1f}MB")

        except Exception as e:
            logger.error(f"Memory optimization failed: {e}")

    def should_optimize_memory(self) -> bool:
        """Check if memory optimization should be triggered."""
        if not self.memory_snapshots:
            return False

        current_memory = self.memory_snapshots[-1].get("process_memory_mb", 0)
        memory_increase = current_memory - self.last_memory_usage

        if memory_increase > self.gc_threshold_mb:
            self.last_memory_usage = current_memory
            return True

        return False

    def get_memory_optimization_suggestions(self) -> List[Dict[str, Any]]:
        """Get memory optimization suggestions."""
        suggestions = []

        if not self.memory_snapshots:
            return suggestions

        current_snapshot = self.memory_snapshots[-1]
        current_memory = current_snapshot.get("process_memory_mb", 0)

        # Check if memory usage is high
        if current_memory > 512:  # 512MB threshold
            suggestions.append({
                "type": "high_memory_usage",
                "priority": "high",
                "description": f"Process memory usage is {current_memory:.1f}MB",
                "recommendation": "Consider implementing object pooling or reducing cache sizes",
                "impact": "High - may cause system instability"
            })

        # Check GC frequency
        if len(self.gc_stats) > 10:
            recent_gc = self.gc_stats[-10:]
            avg_interval = sum(
                (recent_gc[i]["timestamp"] - recent_gc[i-1]["timestamp"]).total_seconds()
                for i in range(1, len(recent_gc))
            ) / (len(recent_gc) - 1)

            if avg_interval < 30:  # GC every 30 seconds is frequent
                suggestions.append({
                    "type": "frequent_gc",
                    "priority": "medium",
                    "description": f"Garbage collection occurring every {avg_interval:.1f} seconds",
                    "recommendation": "Optimize object creation patterns or increase GC thresholds",
                    "impact": "Medium - affects performance consistency"
                })

        return suggestions


class PerformanceOptimizationEngine:
    """Main performance optimization engine."""

    def __init__(self):
        self.monitor = performance_monitor
        self.cache = intelligent_cache
        self.db_optimizer = DatabaseOptimizer()
        self.memory_optimizer = MemoryOptimizer()

        self.optimization_active = False
        self.auto_optimization = True

    async def initialize(self):
        """Initialize optimization engine."""
        logger.info(" Initializing Performance Optimization Engine...")

        # Start monitoring
        self.monitor.start_monitoring()

        # Start optimization loop
        if self.auto_optimization:
            asyncio.create_task(self._optimization_loop())

        logger.info(" Performance Optimization Engine initialized")

    async def _optimization_loop(self):
        """Main optimization loop."""
        self.optimization_active = True

        while self.optimization_active:
            try:
                await asyncio.sleep(60)  # Run every minute

                # Check if optimizations are needed
                await self._check_and_optimize()

            except Exception as e:
                logger.error(f"Optimization loop error: {e}")

    async def _check_and_optimize(self):
        """Check performance and apply optimizations."""
        # Take memory snapshot
        self.memory_optimizer.take_memory_snapshot()

        # Check if memory optimization is needed
        if self.memory_optimizer.should_optimize_memory():
            self.memory_optimizer.optimize_memory()

        # Check performance targets
        summary = self.monitor.get_performance_summary()

        # Apply optimizations based on performance
        if summary["overall_score"] < 70:  # Performance below 70%
            await self._apply_performance_optimizations(summary)

    async def _apply_performance_optimizations(self, summary: Dict[str, Any]):
        """Apply performance optimizations based on current state."""
        logger.info("Applying performance optimizations...")

        # Optimize cache if hit rate is low
        cache_stats = self.cache.get_stats()
        if cache_stats["hit_rate_percent"] < 70:
            # Increase cache size
            self.cache.max_size = min(self.cache.max_size * 2, 50000)
            logger.info(f"Increased cache size to {self.cache.max_size}")

        # Database optimizations
        db_suggestions = self.db_optimizer.get_optimization_suggestions()
        for suggestion in db_suggestions:
            if suggestion["priority"] == "high":
                logger.warning(f"Database optimization needed: {suggestion['description']}")

        # Memory optimizations
        memory_suggestions = self.memory_optimizer.get_memory_optimization_suggestions()
        for suggestion in memory_suggestions:
            if suggestion["priority"] == "high":
                logger.warning(f"Memory optimization needed: {suggestion['description']}")

    def get_comprehensive_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "performance_summary": self.monitor.get_performance_summary(),
            "cache_stats": self.cache.get_stats(),
            "database_performance": self.db_optimizer.get_database_performance_summary(),
            "memory_stats": self.memory_optimizer.memory_snapshots[-1] if self.memory_optimizer.memory_snapshots else {},
            "optimization_suggestions": {
                "database": self.db_optimizer.get_optimization_suggestions(),
                "memory": self.memory_optimizer.get_memory_optimization_suggestions()
            }
        }


# Global instances
performance_monitor = PerformanceMonitor()
intelligent_cache = IntelligentCache()
database_optimizer = DatabaseOptimizer()
memory_optimizer = MemoryOptimizer()
performance_optimization_engine = PerformanceOptimizationEngine()
