"""
Centralized Latency Optimization System

This module provides a comprehensive latency optimization system that consolidates
performance improvements from various modules. It includes request preprocessing,
response compression, caching strategies, and database query optimization.
"""

import asyncio
import gzip
import json
import time
import zlib
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import hashlib
import pickle
from datetime import datetime, timedelta
import threading
import weakref

try:
    from plexichat.core.logging_unified import get_logger, performance_logger
except ImportError:
    # Fallback for backward compatibility
    try:
        from plexichat.core.logging import get_logger
        performance_logger = None
    except ImportError:
        import logging
        get_logger = logging.getLogger
        performance_logger = None


class CompressionType(Enum):
    """Supported compression algorithms."""
    NONE = "none"
    GZIP = "gzip"
    DEFLATE = "deflate"
    BROTLI = "brotli"


class CacheStrategy(Enum):
    """Cache eviction strategies."""
    LRU = "lru"
    LFU = "lfu"
    TTL = "ttl"
    FIFO = "fifo"


@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""
    request_count: int = 0
    total_latency: float = 0.0
    min_latency: float = float('inf')
    max_latency: float = 0.0
    avg_latency: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    compression_ratio: float = 0.0
    db_query_count: int = 0
    db_query_time: float = 0.0
    errors: int = 0
    last_updated: datetime = field(default_factory=datetime.now)

    def update_latency(self, latency: float):
        """Update latency metrics."""
        self.request_count += 1
        self.total_latency += latency
        self.min_latency = min(self.min_latency, latency)
        self.max_latency = max(self.max_latency, latency)
        self.avg_latency = self.total_latency / self.request_count
        self.last_updated = datetime.now()

    def cache_hit(self):
        """Record a cache hit."""
        self.cache_hits += 1

    def cache_miss(self):
        """Record a cache miss."""
        self.cache_misses += 1

    @property
    def cache_hit_ratio(self) -> float:
        """Calculate cache hit ratio."""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0


class RequestPreprocessor:
    """Handles request preprocessing for optimal performance."""

    def __init__(self):
        self.logger = get_logger(__name__)
        self._validation_cache = {}
        self._schema_cache = {}

    async def preprocess_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Preprocess incoming request data for optimal performance.
        
        Args:
            request_data: Raw request data
            
        Returns:
            Preprocessed and optimized request data
        """
        start_time = time.perf_counter()
        
        try:
            # Normalize data structure
            normalized_data = self._normalize_data(request_data)
            
            # Remove unnecessary fields
            cleaned_data = self._clean_data(normalized_data)
            
            # Validate and transform
            validated_data = await self._validate_data(cleaned_data)
            
            # Apply optimizations
            optimized_data = self._optimize_data_structure(validated_data)
            
            processing_time = (time.perf_counter() - start_time) * 1_000_000
            self.logger.debug(f"Request preprocessing completed in {processing_time:.2f}µs")
            
            return optimized_data
            
        except Exception as e:
            self.logger.error(f"Request preprocessing failed: {e}")
            raise

    def _normalize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize data structure and types."""
        normalized = {}
        
        for key, value in data.items():
            # Normalize key names
            normalized_key = key.lower().strip()
            
            # Normalize values
            if isinstance(value, str):
                normalized[normalized_key] = value.strip()
            elif isinstance(value, dict):
                normalized[normalized_key] = self._normalize_data(value)
            elif isinstance(value, list):
                normalized[normalized_key] = [
                    self._normalize_data(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                normalized[normalized_key] = value
                
        return normalized

    def _clean_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove unnecessary or empty fields."""
        cleaned = {}
        
        for key, value in data.items():
            # Skip empty values
            if value is None or value == "" or value == []:
                continue
                
            # Skip internal/debug fields
            if key.startswith('_') or key in ['debug', 'trace', 'internal']:
                continue
                
            if isinstance(value, dict):
                cleaned_value = self._clean_data(value)
                if cleaned_value:  # Only include non-empty dicts
                    cleaned[key] = cleaned_value
            else:
                cleaned[key] = value
                
        return cleaned

    async def _validate_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate data with caching for performance."""
        # Create a hash of the data structure for caching
        data_hash = hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()
        
        if data_hash in self._validation_cache:
            return self._validation_cache[data_hash]
        
        # Perform validation (simplified example)
        validated_data = data.copy()
        
        # Cache the result
        self._validation_cache[data_hash] = validated_data
        
        # Limit cache size
        if len(self._validation_cache) > 1000:
            # Remove oldest entries
            oldest_keys = list(self._validation_cache.keys())[:100]
            for key in oldest_keys:
                del self._validation_cache[key]
        
        return validated_data

    def _optimize_data_structure(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize data structure for faster processing."""
        # Convert to more efficient data structures where possible
        optimized = {}
        
        for key, value in data.items():
            if isinstance(value, list) and len(value) > 100:
                # Convert large lists to sets for faster lookups if appropriate
                if all(isinstance(item, (str, int, float)) for item in value):
                    optimized[key] = set(value) if len(set(value)) == len(value) else value
                else:
                    optimized[key] = value
            else:
                optimized[key] = value
                
        return optimized


class ResponseCompressor:
    """Handles response compression for reduced latency."""

    def __init__(self):
        self.logger = get_logger(__name__)
        self._compression_cache = {}

    async def compress_response(
        self, 
        data: Union[str, bytes, Dict[str, Any]], 
        compression_type: CompressionType = CompressionType.GZIP,
        min_size: int = 1024
    ) -> Tuple[bytes, float]:
        """
        Compress response data.
        
        Args:
            data: Data to compress
            compression_type: Compression algorithm to use
            min_size: Minimum size threshold for compression
            
        Returns:
            Tuple of (compressed_data, compression_ratio)
        """
        start_time = time.perf_counter()
        
        try:
            # Convert data to bytes
            if isinstance(data, dict):
                data_bytes = json.dumps(data, separators=(',', ':')).encode('utf-8')
            elif isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data

            original_size = len(data_bytes)
            
            # Skip compression for small payloads
            if original_size < min_size:
                return data_bytes, 1.0

            # Check cache
            data_hash = hashlib.md5(data_bytes).hexdigest()
            cache_key = f"{data_hash}_{compression_type.value}"
            
            if cache_key in self._compression_cache:
                compressed_data, ratio = self._compression_cache[cache_key]
                self.logger.debug(f"Using cached compression for {original_size} bytes")
                return compressed_data, ratio

            # Perform compression
            if compression_type == CompressionType.GZIP:
                compressed_data = gzip.compress(data_bytes, compresslevel=6)
            elif compression_type == CompressionType.DEFLATE:
                compressed_data = zlib.compress(data_bytes, level=6)
            else:
                # Fallback to no compression
                compressed_data = data_bytes

            compressed_size = len(compressed_data)
            compression_ratio = original_size / compressed_size if compressed_size > 0 else 1.0

            # Cache the result
            self._compression_cache[cache_key] = (compressed_data, compression_ratio)
            
            # Limit cache size
            if len(self._compression_cache) > 500:
                oldest_keys = list(self._compression_cache.keys())[:50]
                for key in oldest_keys:
                    del self._compression_cache[key]

            compression_time = (time.perf_counter() - start_time) * 1_000_000
            self.logger.debug(
                f"Compressed {original_size} bytes to {compressed_size} bytes "
                f"(ratio: {compression_ratio:.2f}) in {compression_time:.2f}µs"
            )

            return compressed_data, compression_ratio

        except Exception as e:
            self.logger.error(f"Response compression failed: {e}")
            # Return original data on compression failure
            if isinstance(data, (str, dict)):
                return json.dumps(data).encode('utf-8') if isinstance(data, dict) else data.encode('utf-8'), 1.0
            return data, 1.0


class AdvancedCache:
    """Advanced caching system with multiple strategies."""

    def __init__(self, max_size: int = 10000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.logger = get_logger(__name__)
        
        # Storage
        self._cache = {}
        self._access_times = {}
        self._access_counts = defaultdict(int)
        self._expiry_times = {}
        self._insertion_order = deque()
        
        # Thread safety
        self._lock = threading.RLock()

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self._lock:
            if key not in self._cache:
                return None
                
            # Check expiry
            if key in self._expiry_times and datetime.now() > self._expiry_times[key]:
                await self._remove(key)
                return None
                
            # Update access patterns
            self._access_times[key] = datetime.now()
            self._access_counts[key] += 1
            
            return self._cache[key]

    async def set(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None,
        strategy: CacheStrategy = CacheStrategy.LRU
    ):
        """Set value in cache."""
        with self._lock:
            # Set expiry
            if ttl is None:
                ttl = self.default_ttl
            self._expiry_times[key] = datetime.now() + timedelta(seconds=ttl)
            
            # Add to cache
            if key not in self._cache:
                self._insertion_order.append(key)
                
            self._cache[key] = value
            self._access_times[key] = datetime.now()
            self._access_counts[key] = 1
            
            # Evict if necessary
            if len(self._cache) > self.max_size:
                await self._evict(strategy)

    async def _evict(self, strategy: CacheStrategy):
        """Evict items based on strategy."""
        if strategy == CacheStrategy.LRU:
            # Remove least recently used
            oldest_key = min(self._access_times.keys(), key=lambda k: self._access_times[k])
            await self._remove(oldest_key)
            
        elif strategy == CacheStrategy.LFU:
            # Remove least frequently used
            least_used_key = min(self._access_counts.keys(), key=lambda k: self._access_counts[k])
            await self._remove(least_used_key)
            
        elif strategy == CacheStrategy.FIFO:
            # Remove first inserted
            if self._insertion_order:
                oldest_key = self._insertion_order.popleft()
                await self._remove(oldest_key)
                
        elif strategy == CacheStrategy.TTL:
            # Remove expired items first
            now = datetime.now()
            expired_keys = [
                key for key, expiry in self._expiry_times.items()
                if expiry <= now
            ]
            for key in expired_keys:
                await self._remove(key)

    async def _remove(self, key: str):
        """Remove key from all data structures."""
        self._cache.pop(key, None)
        self._access_times.pop(key, None)
        self._access_counts.pop(key, None)
        self._expiry_times.pop(key, None)
        
        try:
            self._insertion_order.remove(key)
        except ValueError:
            pass

    async def clear(self):
        """Clear all cache data."""
        with self._lock:
            self._cache.clear()
            self._access_times.clear()
            self._access_counts.clear()
            self._expiry_times.clear()
            self._insertion_order.clear()

    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'hit_ratio': self._calculate_hit_ratio(),
                'expired_count': self._count_expired()
            }

    def _calculate_hit_ratio(self) -> float:
        """Calculate cache hit ratio."""
        total_accesses = sum(self._access_counts.values())
        return len(self._cache) / total_accesses if total_accesses > 0 else 0.0

    def _count_expired(self) -> int:
        """Count expired entries."""
        now = datetime.now()
        return sum(1 for expiry in self._expiry_times.values() if expiry <= now)


class DatabaseQueryOptimizer:
    """Optimizes database queries for reduced latency."""

    def __init__(self):
        self.logger = get_logger(__name__)
        self._query_cache = AdvancedCache(max_size=1000, default_ttl=300)
        self._query_stats = defaultdict(lambda: {'count': 0, 'total_time': 0.0})
        self._batch_queue = defaultdict(list)
        self._batch_lock = threading.Lock()

    async def execute_query(
        self, 
        query: str, 
        params: Optional[Tuple] = None,
        cache_key: Optional[str] = None,
        cache_ttl: int = 300
    ) -> Any:
        """
        Execute optimized database query.
        
        Args:
            query: SQL query string
            params: Query parameters
            cache_key: Optional cache key for result caching
            cache_ttl: Cache time-to-live in seconds
            
        Returns:
            Query result
        """
        start_time = time.perf_counter()
        
        try:
            # Generate cache key if not provided
            if cache_key is None:
                cache_key = self._generate_cache_key(query, params)

            # Check cache first
            cached_result = await self._query_cache.get(cache_key)
            if cached_result is not None:
                self.logger.debug(f"Cache hit for query: {query[:50]}...")
                return cached_result

            # Execute query (this would integrate with actual DB connection)
            result = await self._execute_raw_query(query, params)
            
            # Cache the result
            await self._query_cache.set(cache_key, result, ttl=cache_ttl)
            
            # Update statistics
            execution_time = time.perf_counter() - start_time
            self._update_query_stats(query, execution_time)
            
            self.logger.debug(f"Query executed in {execution_time * 1000:.2f}ms")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Query execution failed: {e}")
            raise

    async def batch_execute(self, queries: List[Tuple[str, Optional[Tuple]]]) -> List[Any]:
        """
        Execute multiple queries in batch for better performance.
        
        Args:
            queries: List of (query, params) tuples
            
        Returns:
            List of query results
        """
        start_time = time.perf_counter()
        
        try:
            results = []
            
            # Group similar queries
            grouped_queries = self._group_similar_queries(queries)
            
            for group in grouped_queries:
                if len(group) == 1:
                    # Single query
                    query, params = group[0]
                    result = await self.execute_query(query, params)
                    results.append(result)
                else:
                    # Batch execution
                    batch_results = await self._execute_batch(group)
                    results.extend(batch_results)
            
            execution_time = time.perf_counter() - start_time
            self.logger.debug(f"Batch execution completed in {execution_time * 1000:.2f}ms")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Batch execution failed: {e}")
            raise

    def _generate_cache_key(self, query: str, params: Optional[Tuple]) -> str:
        """Generate cache key for query and parameters."""
        query_hash = hashlib.md5(query.encode()).hexdigest()
        if params:
            params_hash = hashlib.md5(str(params).encode()).hexdigest()
            return f"query_{query_hash}_{params_hash}"
        return f"query_{query_hash}"

    async def _execute_raw_query(self, query: str, params: Optional[Tuple]) -> Any:
        """Execute raw database query (placeholder for actual implementation)."""
        # This would integrate with the actual database connection
        # For now, simulate query execution
        await asyncio.sleep(0.001)  # Simulate DB latency
        return {"result": "simulated_data", "query": query[:50]}

    def _group_similar_queries(self, queries: List[Tuple[str, Optional[Tuple]]]) -> List[List[Tuple[str, Optional[Tuple]]]]:
        """Group similar queries for batch execution."""
        groups = defaultdict(list)
        
        for query, params in queries:
            # Simple grouping by query template
            query_template = self._extract_query_template(query)
            groups[query_template].append((query, params))
        
        return list(groups.values())

    def _extract_query_template(self, query: str) -> str:
        """Extract query template for grouping."""
        # Simple template extraction (replace values with placeholders)
        import re
        template = re.sub(r'\b\d+\b', '?', query)  # Replace numbers
        template = re.sub(r"'[^']*'", '?', template)  # Replace strings
        return template

    async def _execute_batch(self, queries: List[Tuple[str, Optional[Tuple]]]) -> List[Any]:
        """Execute batch of similar queries."""
        # Placeholder for actual batch execution
        results = []
        for query, params in queries:
            result = await self._execute_raw_query(query, params)
            results.append(result)
        return results

    def _update_query_stats(self, query: str, execution_time: float):
        """Update query execution statistics."""
        query_template = self._extract_query_template(query)
        stats = self._query_stats[query_template]
        stats['count'] += 1
        stats['total_time'] += execution_time
        stats['avg_time'] = stats['total_time'] / stats['count']

    def get_query_stats(self) -> Dict[str, Any]:
        """Get query execution statistics."""
        return dict(self._query_stats)


class LatencyOptimizer:
    """Main latency optimization coordinator."""

    def __init__(self):
        self.logger = get_logger(__name__)
        self.performance_logger = performance_logger
        
        # Components
        self.preprocessor = RequestPreprocessor()
        self.compressor = ResponseCompressor()
        self.cache = AdvancedCache()
        self.db_optimizer = DatabaseQueryOptimizer()
        
        # Metrics
        self.metrics = PerformanceMetrics()
        self._metrics_lock = threading.Lock()

    @asynccontextmanager
    async def optimize_request(self, request_id: str = None):
        """
        Context manager for request optimization.
        
        Usage:
            async with optimizer.optimize_request("req_123") as ctx:
                # Process request
                result = await process_request(data)
        """
        start_time = time.perf_counter()
        request_id = request_id or f"req_{int(time.time() * 1000000)}"
        
        self.logger.debug(f"Starting optimization for request {request_id}")
        
        try:
            # Create optimization context
            context = OptimizationContext(
                request_id=request_id,
                start_time=start_time,
                optimizer=self
            )
            
            yield context
            
        except Exception as e:
            self.logger.error(f"Request optimization failed for {request_id}: {e}")
            with self._metrics_lock:
                self.metrics.errors += 1
            raise
            
        finally:
            # Update metrics
            total_time = time.perf_counter() - start_time
            with self._metrics_lock:
                self.metrics.update_latency(total_time)
            
            if self.performance_logger:
                self.performance_logger.log_performance_metric(
                    "request_latency",
                    total_time * 1000,  # Convert to milliseconds
                    {"request_id": request_id}
                )
            
            self.logger.debug(f"Request {request_id} completed in {total_time * 1000:.2f}ms")

    async def preprocess_request(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Preprocess request data."""
        return await self.preprocessor.preprocess_request(data)

    async def compress_response(
        self, 
        data: Union[str, bytes, Dict[str, Any]], 
        compression_type: CompressionType = CompressionType.GZIP
    ) -> Tuple[bytes, float]:
        """Compress response data."""
        compressed_data, ratio = await self.compressor.compress_response(data, compression_type)
        
        with self._metrics_lock:
            self.metrics.compression_ratio = (
                self.metrics.compression_ratio + ratio
            ) / 2  # Running average
        
        return compressed_data, ratio

    async def cache_get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        result = await self.cache.get(key)
        
        with self._metrics_lock:
            if result is not None:
                self.metrics.cache_hit()
            else:
                self.metrics.cache_miss()
        
        return result

    async def cache_set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache."""
        await self.cache.set(key, value, ttl)

    async def execute_query(
        self, 
        query: str, 
        params: Optional[Tuple] = None,
        cache_key: Optional[str] = None
    ) -> Any:
        """Execute optimized database query."""
        start_time = time.perf_counter()
        
        try:
            result = await self.db_optimizer.execute_query(query, params, cache_key)
            
            query_time = time.perf_counter() - start_time
            with self._metrics_lock:
                self.metrics.db_query_count += 1
                self.metrics.db_query_time += query_time
            
            return result
            
        except Exception as e:
            self.logger.error(f"Optimized query execution failed: {e}")
            raise

    def get_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        with self._metrics_lock:
            return {
                'requests': {
                    'count': self.metrics.request_count,
                    'avg_latency_ms': self.metrics.avg_latency * 1000,
                    'min_latency_ms': self.metrics.min_latency * 1000,
                    'max_latency_ms': self.metrics.max_latency * 1000,
                },
                'cache': {
                    'hit_ratio': self.metrics.cache_hit_ratio,
                    'hits': self.metrics.cache_hits,
                    'misses': self.metrics.cache_misses,
                },
                'compression': {
                    'avg_ratio': self.metrics.compression_ratio,
                },
                'database': {
                    'query_count': self.metrics.db_query_count,
                    'total_time_ms': self.metrics.db_query_time * 1000,
                    'avg_time_ms': (
                        self.metrics.db_query_time / self.metrics.db_query_count * 1000
                        if self.metrics.db_query_count > 0 else 0
                    ),
                },
                'errors': self.metrics.errors,
                'last_updated': self.metrics.last_updated.isoformat(),
            }

    async def reset_metrics(self):
        """Reset performance metrics."""
        with self._metrics_lock:
            self.metrics = PerformanceMetrics()

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on optimization components."""
        health = {
            'status': 'healthy',
            'components': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Check cache
            test_key = f"health_check_{int(time.time())}"
            await self.cache.set(test_key, "test", ttl=1)
            cached_value = await self.cache.get(test_key)
            health['components']['cache'] = 'healthy' if cached_value == "test" else 'unhealthy'
            
            # Check database optimizer
            health['components']['database'] = 'healthy'  # Simplified check
            
            # Check preprocessor
            test_data = {'test': 'data'}
            processed = await self.preprocessor.preprocess_request(test_data)
            health['components']['preprocessor'] = 'healthy' if processed else 'unhealthy'
            
            # Check compressor
            test_response = "test response data"
            compressed, ratio = await self.compressor.compress_response(test_response)
            health['components']['compressor'] = 'healthy' if compressed else 'unhealthy'
            
        except Exception as e:
            health['status'] = 'unhealthy'
            health['error'] = str(e)
            self.logger.error(f"Health check failed: {e}")
        
        return health


@dataclass
class OptimizationContext:
    """Context for request optimization."""
    request_id: str
    start_time: float
    optimizer: LatencyOptimizer
    _cached_data: Dict[str, Any] = field(default_factory=dict)

    async def cache_get(self, key: str) -> Optional[Any]:
        """Get from cache with context."""
        return await self.optimizer.cache_get(f"{self.request_id}:{key}")

    async def cache_set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set in cache with context."""
        await self.optimizer.cache_set(f"{self.request_id}:{key}", value, ttl)

    def get_elapsed_time(self) -> float:
        """Get elapsed time since request start."""
        return time.perf_counter() - self.start_time


# Decorator for automatic optimization
def optimize_latency(
    cache_key_func: Optional[Callable] = None,
    cache_ttl: int = 300,
    compress_response: bool = True,
    preprocess_request: bool = True
):
    """
    Decorator for automatic latency optimization.
    
    Args:
        cache_key_func: Function to generate cache key
        cache_ttl: Cache time-to-live in seconds
        compress_response: Whether to compress response
        preprocess_request: Whether to preprocess request
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            optimizer = LatencyOptimizer()
            
            # Generate cache key
            if cache_key_func:
                cache_key = cache_key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"
            
            # Check cache first
            cached_result = await optimizer.cache_get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Preprocess request if enabled
            if preprocess_request and args:
                if isinstance(args[0], dict):
                    args = (await optimizer.preprocess_request(args[0]),) + args[1:]
            
            # Execute function
            async with optimizer.optimize_request() as ctx:
                result = await func(*args, **kwargs)
            
            # Cache result
            await optimizer.cache_set(cache_key, result, ttl=cache_ttl)
            
            # Compress response if enabled
            if compress_response and isinstance(result, (str, dict, bytes)):
                compressed_result, _ = await optimizer.compress_response(result)
                return compressed_result
            
            return result
        
        return wrapper
    return decorator


# Global optimizer instance
_global_optimizer = None


def get_optimizer() -> LatencyOptimizer:
    """Get global optimizer instance."""
    global _global_optimizer
    if _global_optimizer is None:
        _global_optimizer = LatencyOptimizer()
    return _global_optimizer


# Convenience functions
async def optimize_request_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Optimize request data using global optimizer."""
    optimizer = get_optimizer()
    return await optimizer.preprocess_request(data)


async def compress_response_data(
    data: Union[str, bytes, Dict[str, Any]], 
    compression_type: CompressionType = CompressionType.GZIP
) -> Tuple[bytes, float]:
    """Compress response data using global optimizer."""
    optimizer = get_optimizer()
    return await optimizer.compress_response(data, compression_type)


async def cached_query(
    query: str, 
    params: Optional[Tuple] = None,
    cache_key: Optional[str] = None
) -> Any:
    """Execute cached database query using global optimizer."""
    optimizer = get_optimizer()
    return await optimizer.execute_query(query, params, cache_key)


async def get_performance_metrics() -> Dict[str, Any]:
    """Get performance metrics from global optimizer."""
    optimizer = get_optimizer()
    return optimizer.get_metrics()