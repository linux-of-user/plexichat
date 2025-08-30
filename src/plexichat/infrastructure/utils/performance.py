# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import logging
import time
from datetime import datetime
from functools import wraps
from typing import Any, Callable, Dict, Optional
import psutil

# Use EXISTING performance optimization engine
try:
    from plexichat.core.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None
    timer = None

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

class PerformanceTracker:
    """Performance tracking using EXISTING systems."""
    def __init__(self):
        self.performance_logger = performance_logger
        self.optimization_engine = optimization_engine
        self.metrics: Dict[str, Any] = {}
        self.start_times: Dict[str, float] = {}

    def start_timer(self, operation: str):
        """Start timing an operation."""
        self.start_times[operation] = time.time()

    def end_timer(self, operation: str) -> float:
        """End timing and return duration."""
        if operation in self.start_times:
            duration = time.time() - self.start_times[operation]
            del self.start_times[operation]

            # Log to EXISTING performance logger
            if self.performance_logger:
                self.performance_logger.record_metric(f"{operation}_duration", duration, "seconds")

            return duration
        return 0.0

    def record_metric(self, name: str, value: Any, unit: str = "count"):
        """Record performance metric."""
        if self.performance_logger:
            self.performance_logger.record_metric(name, value, unit)

        # Store locally as well
        self.metrics[name] = {"value": value, "unit": unit, "timestamp": datetime.now()}

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics."""
        return self.metrics.copy()

# Global performance tracker
performance_tracker = PerformanceTracker()

def async_track_performance(operation_name: str):
    """Decorator to track async function performance."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                # Use EXISTING timer if available
                if performance_logger and timer:
                    with timer(operation_name):
                        result = await func(*args, **kwargs)
                else:
                    result = await func(*args, **kwargs)

                # Track success
                performance_tracker.record_metric(f"{operation_name}_success", 1)

                return result

            except Exception as e:
                # Track failure
                performance_tracker.record_metric(f"{operation_name}_failure", 1)
                logger.error(f"Performance tracking error in {operation_name}: {e}")
                raise
            finally:
                # Track duration
                duration = time.time() - start_time
                performance_tracker.record_metric(f"{operation_name}_duration", duration, "seconds")

        return wrapper
    return decorator

def track_performance(operation_name: str):
    """Decorator to track sync function performance."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                # Use EXISTING timer if available
                if performance_logger and timer:
                    with timer(operation_name):
                        result = func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                # Track success
                performance_tracker.record_metric(f"{operation_name}_success", 1)

                return result

            except Exception as e:
                # Track failure
                performance_tracker.record_metric(f"{operation_name}_failure", 1)
                logger.error(f"Performance tracking error in {operation_name}: {e}")
                raise
            finally:
                # Track duration
                duration = time.time() - start_time
                performance_tracker.record_metric(f"{operation_name}_duration", duration, "seconds")

        return wrapper
    return decorator

class PerformanceOptimizer:
    """Performance optimizer using EXISTING systems."""
    def __init__(self):
        self.optimization_engine = optimization_engine
        self.performance_logger = performance_logger

    async def optimize_query(self, query: str, params: Dict[str, Any]) -> str:
        """Optimize database query using EXISTING optimization engine."""
        try:
            if self.optimization_engine:
                return await self.optimization_engine.optimize_query(query, params)
            return query
        except Exception as e:
            logger.error(f"Query optimization error: {e}")
            return query

    async def cache_result(self, key: str, value: Any, ttl: int = 300):
        """Cache result using EXISTING optimization engine."""
        try:
            if self.optimization_engine:
                await self.optimization_engine.cache_set(key, value, ttl)
        except Exception as e:
            logger.error(f"Cache set error: {e}")

    async def get_cached_result(self, key: str) -> Optional[Any]:
        """Get cached result using EXISTING optimization engine."""
        try:
            if self.optimization_engine:
                return await self.optimization_engine.cache_get(key)
            return None
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None

# Global performance optimizer
performance_optimizer = PerformanceOptimizer()

# Convenience functions
def start_timer(operation: str):
    """Start timing operation."""
    performance_tracker.start_timer(operation)

def end_timer(operation: str) -> float:
    """End timing operation."""
    return performance_tracker.end_timer(operation)

def record_metric(name: str, value: Any, unit: str = "count"):
    """Record performance metric."""
    performance_tracker.record_metric(name, value, unit)

def get_performance_metrics() -> Dict[str, Any]:
    """Get current performance metrics."""
    return performance_tracker.get_metrics()

# Cache decorator
def cache_result(ttl: int = 300, key_func: Optional[Callable] = None):
    """Decorator to cache function results."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"

            # Try to get from cache
            cached_result = await performance_optimizer.get_cached_result(cache_key)
            if cached_result is not None:
                record_metric("cache_hits", 1)
                return cached_result

            # Execute function
            result = await func(*args, **kwargs)

            # Cache result
            await performance_optimizer.cache_result(cache_key, result, ttl)
            record_metric("cache_misses", 1)

            return result

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For sync functions, just execute without caching
            return func(*args, **kwargs)

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator

# Rate limiting
class RateLimiter:
    """Simple rate limiter."""
    def __init__(self):
        self.requests: Dict[str, list] = {}

    def is_allowed(self, key: str, limit: int, window: int) -> bool:
        """Check if request is allowed."""
        now = time.time()

        if key not in self.requests:
            self.requests[key] = []

        # Clean old requests
        self.requests[key] = [req_time for req_time in self.requests[key] if now - req_time < window]

        # Check limit
        if len(self.requests[key]) >= limit:
            return False

        # Add current request
        self.requests[key].append(now)
        return True

# Global rate limiter
rate_limiter = RateLimiter()

def rate_limit(limit: int, window: int = 60, key_func: Optional[Callable] = None):
    """Rate limiting decorator."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Generate rate limit key
            if key_func:
                rate_key = key_func(*args, **kwargs)
            else:
                rate_key = f"{func.__name__}_default"

            if not rate_limiter.is_allowed(rate_key, limit, window):
                from fastapi import HTTPException, status
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded"
                )

            return await func(*args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Generate rate limit key
            if key_func:
                rate_key = key_func(*args, **kwargs)
            else:
                rate_key = f"{func.__name__}_default"

            if not rate_limiter.is_allowed(rate_key, limit, window):
                raise Exception("Rate limit exceeded")

            return func(*args, **kwargs)

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator

# Memory monitoring
def get_memory_usage() -> Dict[str, Any]:
    """Get current memory usage."""
    try:
        process = psutil.Process()
        memory_info = process.memory_info()

        return {
            "rss": memory_info.rss,
            "vms": memory_info.vms,
            "percent": process.memory_percent(),
            "available": psutil.virtual_memory().available
        }
    except ImportError:
        return {"error": "psutil not available"}
    except Exception as e:
        return {"error": str(e)}

# CPU monitoring
def get_cpu_usage() -> Dict[str, Any]:
    """Get current CPU usage."""
    try:
        return {
            "percent": psutil.cpu_percent(interval=1),
            "count": psutil.cpu_count(),
            "load_avg": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
        }
    except ImportError:
        return {"error": "psutil not available"}
    except Exception as e:
        return {"error": str(e)}

# System monitoring
def get_system_stats() -> Dict[str, Any]:
    """Get comprehensive system statistics."""
    return {
        "memory": get_memory_usage(),
        "cpu": get_cpu_usage(),
        "performance_metrics": get_performance_metrics(),
        "timestamp": datetime.now().isoformat()
    }
